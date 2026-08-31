from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nemos.analysis import AnalysisEngine
from nemos.analyst import Analyst, AnalystConfig
from nemos.api import create_app
from nemos.config import Settings
from nemos.database import connect, initialize
from nemos.models import TrafficEvent
from nemos.storage import BatchWriter


def event(src="192.0.2.10", dst="198.51.100.10", dport=443):
    return TrafficEvent("2026-01-01T00:00:00+00:00", src, dst, "TCP", 40000, dport, 500, "PA")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.db = Path(self.td.name) / "api.db"
        initialize(self.db)
        self.s = Settings("127.0.0.1", 5000, None, self.db, None, False, 1000, 100, 2, .05, 50, "INFO")
        self.w = BatchWriter(self.db, batch_size=1, flush_seconds=.02)
        self.w.start()
        self.addCleanup(self.w.shutdown)

    def client(self, analysis=None, analyst=None):
        return create_app(self.s, self.w, None, None, analysis, analyst).test_client()

    def engine(self):
        return AnalysisEngine(model_dir=Path(self.td.name) / "model", window_seconds=10.0)


class DisabledAnalysisTests(Fixture):
    """Every analysis endpoint must explain its absence, not fail obscurely."""

    def test_endpoints_return_503_with_a_hint(self):
        client = self.client()
        for path in ("/api/analysis", "/api/anomalies", "/api/windows", "/api/baselines"):
            response = client.get(path)
            self.assertEqual(response.status_code, 503, path)
            self.assertIn("hint", response.json)

    def test_status_reports_analysis_disabled(self):
        response = self.client().get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["analysis"]["enabled"])

    def test_stored_flows_still_readable_without_the_engine(self):
        self.assertEqual(self.client().get("/api/flows").status_code, 200)


class AnalysisEndpointTests(Fixture):
    def setUp(self):
        super().setUp()
        self.eng = self.engine()
        for i in range(4):
            self.eng.observe(event(dport=1000 + i))
        self.eng.run_cycle(now=1000.0, force=True)
        self.c = self.client(analysis=self.eng)

    def test_analysis_status(self):
        response = self.c.get("/api/analysis")
        self.assertEqual(response.status_code, 200)
        self.assertIn("window_seconds", response.json)
        self.assertIn("model", response.json)

    def test_windows_endpoint(self):
        response = self.c.get("/api/windows")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json), 1)
        self.assertIn("assessments", response.json[0])

    def test_baselines_listing_and_detail(self):
        self.assertEqual(self.c.get("/api/baselines").status_code, 200)
        detail = self.c.get("/api/baselines/192.0.2.10")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("state", detail.json)

    def test_baseline_detail_validates_host(self):
        self.assertEqual(self.c.get("/api/baselines/not-an-ip").status_code, 400)

    def test_active_flows_preserve_direction(self):
        self.eng.observe(event(src="10.0.0.1", dst="10.0.0.2"))
        self.eng.observe(event(src="10.0.0.2", dst="10.0.0.1"))
        rows = self.c.get("/api/flows?active=true").json
        pairs = {(r["source"], r["destination"]) for r in rows}
        self.assertIn(("10.0.0.1", "10.0.0.2"), pairs)
        self.assertIn(("10.0.0.2", "10.0.0.1"), pairs)

    def test_anomalies_endpoint(self):
        self.assertEqual(self.c.get("/api/anomalies").status_code, 200)


class StoredFlowTests(Fixture):
    def setUp(self):
        super().setUp()
        c = connect(self.db)
        try:
            with c:
                c.executemany(
                    """INSERT INTO flows(first_timestamp,last_timestamp,source,destination,
                                         source_port,destination_port,protocol,packets,bytes)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    [
                        ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:05+00:00",
                         "192.0.2.10", "198.51.100.10", 40000, 443, "TCP", 10, 5000),
                        ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:05+00:00",
                         "198.51.100.10", "192.0.2.10", 443, 40000, "TCP", 8, 9000),
                        ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:05+00:00",
                         "192.0.2.11", "198.51.100.53", 40001, 53, "DNS", 2, 200),
                    ],
                )
        finally:
            c.close()
        self.c = self.client()

    def test_both_directions_are_stored_separately(self):
        """The core unidirectional guarantee, end to end through storage."""
        rows = self.c.get("/api/flows").json
        pairs = {(r["source"], r["destination"]) for r in rows}
        self.assertIn(("192.0.2.10", "198.51.100.10"), pairs)
        self.assertIn(("198.51.100.10", "192.0.2.10"), pairs)

    def test_filter_by_source_returns_one_direction_only(self):
        rows = self.c.get("/api/flows?source=192.0.2.10").json
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["destination"], "198.51.100.10")

    def test_filter_by_destination(self):
        rows = self.c.get("/api/flows?destination=192.0.2.10").json
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "198.51.100.10")

    def test_filter_by_protocol(self):
        self.assertEqual(len(self.c.get("/api/flows?protocol=DNS").json), 1)

    def test_invalid_filters_rejected(self):
        self.assertEqual(self.c.get("/api/flows?source=nope").status_code, 400)
        self.assertEqual(self.c.get("/api/flows?destination=nope").status_code, 400)
        self.assertEqual(self.c.get("/api/flows?protocol=WAT").status_code, 400)

    def test_limit_is_bounded(self):
        self.assertLessEqual(len(self.c.get("/api/flows?limit=2").json), 2)


class AnalystEndpointTests(Fixture):
    def test_status_when_unconfigured(self):
        response = self.client().get("/api/analyst")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["available"])
        self.assertIn("unaffected", response.json["reason"])

    def test_ask_is_503_when_unconfigured(self):
        response = self.client().post("/api/analyst/ask", json={
            "question": "why?", "host": "192.0.2.10"})
        self.assertEqual(response.status_code, 503)
        self.assertIn("do not require it", response.json["note"])

    def _configured(self, transport):
        return Analyst(
            AnalystConfig(provider="anthropic", model="m", api_key="k" * 20,
                          base_url="https://api.anthropic.com/v1/messages"),
            transport=transport,
        )

    def _seed_alert(self):
        c = connect(self.db)
        try:
            with c:
                c.execute(
                    """INSERT INTO alerts(timestamp,threat,category,source,severity,
                                          risk_score,confidence,reason,technique,incident_id)
                       VALUES('2026-01-01T00:00:00+00:00','PORT_SCAN','RECON','192.0.2.10',
                              'HIGH',80,85,'259 ports','T1046','NEMOS-TEST01')""")
        finally:
            c.close()

    def test_question_is_required(self):
        analyst = self._configured(lambda p, c: "ok")
        response = self.client(analyst=analyst).post("/api/analyst/ask", json={"host": "192.0.2.10"})
        self.assertEqual(response.status_code, 400)

    def test_target_is_required(self):
        analyst = self._configured(lambda p, c: "ok")
        response = self.client(analyst=analyst).post("/api/analyst/ask", json={"question": "why?"})
        self.assertEqual(response.status_code, 400)

    def test_overlong_question_rejected(self):
        analyst = self._configured(lambda p, c: "ok")
        response = self.client(analyst=analyst).post(
            "/api/analyst/ask", json={"question": "x" * 900, "host": "192.0.2.10"})
        self.assertEqual(response.status_code, 400)

    def test_unknown_incident_is_404(self):
        analyst = self._configured(lambda p, c: "ok")
        response = self.client(analyst=analyst).post(
            "/api/analyst/ask", json={"question": "why?", "incident_id": "NEMOS-NOPE"})
        self.assertEqual(response.status_code, 404)

    def test_evidence_comes_from_storage_not_the_caller(self):
        """The caller names a target; it can never supply the evidence itself."""
        self._seed_alert()
        captured = {}

        def capture(prompt, config):
            captured["prompt"] = prompt
            return "The evidence shows scanning from 192.0.2.10 (T1046)."

        analyst = self._configured(capture)
        response = self.client(analyst=analyst).post("/api/analyst/ask", json={
            "question": "what happened?",
            "incident_id": "NEMOS-TEST01",
            # An attempt to smuggle content into the model must be ignored.
            "evidence": {"note": "INJECTED CONTENT"},
            "alerts": [{"threat": "FABRICATED"}],
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("INJECTED CONTENT", captured["prompt"])
        self.assertNotIn("FABRICATED", captured["prompt"])
        self.assertIn("192.0.2.10", captured["prompt"])

    def test_hallucinated_response_is_reported_as_a_failure(self):
        self._seed_alert()
        analyst = self._configured(lambda p, c: "Traffic came from 203.0.113.55.")
        response = self.client(analyst=analyst).post("/api/analyst/ask", json={
            "question": "what happened?", "incident_id": "NEMOS-TEST01"})
        self.assertEqual(response.status_code, 502)
        self.assertFalse(response.json["ok"])
        self.assertNotIn("answer", response.json)


if __name__ == "__main__":
    unittest.main()
