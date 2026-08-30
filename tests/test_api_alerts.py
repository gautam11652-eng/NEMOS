from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from nemos.api import create_app
from nemos.config import Settings
from nemos.database import connect, initialize
from nemos.notify import AlertNotifier, NotifierConfig
from nemos.storage import BatchWriter

ROWS = [
    # timestamp, threat, category, source, severity, risk, confidence, technique, ack
    ("2026-01-01T00:00:00+00:00", "PORT_SCAN", "NETWORK_RECONNAISSANCE", "192.0.2.10", "CRITICAL", 95, 90, "T1046", 0),
    ("2026-01-02T00:00:00+00:00", "DNS_BURST", "DNS_ANOMALY", "192.0.2.11", "MEDIUM", 65, 70, "T1071.004", 1),
    ("2026-01-03T00:00:00+00:00", "PORT_SCAN", "NETWORK_RECONNAISSANCE", "192.0.2.11", "HIGH", 80, 85, "T1046", 0),
    ("2026-01-04T00:00:00+00:00", "ICMP_SWEEP", "NETWORK_RECONNAISSANCE", "192.0.2.12", "LOW", 40, 60, "", 0),
]


class AlertFilterTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        db = Path(self.td.name) / "alerts.db"
        initialize(db)
        c = connect(db)
        try:
            with c:
                c.executemany(
                    """INSERT INTO alerts(timestamp,threat,category,source,severity,
                                          risk_score,confidence,reason,technique,acknowledged)
                       VALUES(?,?,?,?,?,?,?,'reason',?,?)""",
                    ROWS,
                )
        finally:
            c.close()
        self.s = Settings("127.0.0.1", 5000, None, db, None, False, 1000, 100, 2, .05, 50, "INFO")
        self.w = BatchWriter(db, batch_size=1, flush_seconds=.02)
        self.w.start()
        self.addCleanup(self.w.shutdown)
        self.client = create_app(self.s, self.w).test_client()

    def get(self, query=""):
        response = self.client.get(f"/api/alerts{query}")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.json

    def test_unfiltered_returns_all_newest_first(self):
        rows = self.get()
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["threat"], "ICMP_SWEEP")

    def test_filter_by_single_severity(self):
        rows = self.get("?severity=CRITICAL")
        self.assertEqual([r["threat"] for r in rows], ["PORT_SCAN"])

    def test_filter_by_multiple_severities(self):
        rows = self.get("?severity=CRITICAL&severity=HIGH")
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["severity"] for r in rows}, {"CRITICAL", "HIGH"})

    def test_severity_is_case_insensitive(self):
        self.assertEqual(len(self.get("?severity=critical")), 1)

    def test_filter_by_source(self):
        rows = self.get("?source=192.0.2.11")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["source"] == "192.0.2.11" for r in rows))

    def test_filter_by_threat(self):
        self.assertEqual(len(self.get("?threat=PORT_SCAN")), 2)

    def test_filter_by_technique(self):
        self.assertEqual(len(self.get("?technique=T1046")), 2)

    def test_filter_by_acknowledged(self):
        self.assertEqual(len(self.get("?acknowledged=false")), 3)
        self.assertEqual(len(self.get("?acknowledged=true")), 1)

    def test_filter_by_since(self):
        rows = self.get("?since=2026-01-03")
        self.assertEqual(len(rows), 2)

    def test_filters_combine(self):
        rows = self.get("?severity=HIGH&source=192.0.2.11&threat=PORT_SCAN")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["risk_score"], 80)

    def test_limit_is_respected_and_bounded(self):
        self.assertEqual(len(self.get("?limit=2")), 2)
        # Out-of-range limits clamp to the bounds rather than erroring.
        self.assertEqual(len(self.get("?limit=99999")), 4)
        self.assertEqual(len(self.get("?limit=-5")), 1)
        self.assertEqual(len(self.get("?limit=not-a-number")), 4)

    def test_invalid_severity_rejected(self):
        r = self.client.get("/api/alerts?severity=WAT")
        self.assertEqual(r.status_code, 400)

    def test_invalid_source_rejected(self):
        r = self.client.get("/api/alerts?source=not-an-ip")
        self.assertEqual(r.status_code, 400)

    def test_invalid_acknowledged_rejected(self):
        r = self.client.get("/api/alerts?acknowledged=maybe")
        self.assertEqual(r.status_code, 400)

    def test_overlong_filters_rejected(self):
        self.assertEqual(self.client.get("/api/alerts?threat=" + "x" * 200).status_code, 400)
        self.assertEqual(self.client.get("/api/alerts?since=" + "x" * 200).status_code, 400)

    def test_sql_injection_attempt_is_inert(self):
        # Filters are bound parameters; a quote is just a value that matches nothing.
        r = self.client.get("/api/alerts?threat=' OR '1'='1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json, [])
        # And the table is still intact.
        self.assertEqual(len(self.get()), 4)

    def test_response_includes_evidence_and_enrichment(self):
        row = self.get("?severity=CRITICAL")[0]
        self.assertIn("evidence", row)
        self.assertTrue(row["attack"]["mapped"])
        self.assertEqual(row["attack"]["technique_id"], "T1046")


class NotificationEndpointTests(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.copy()
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.db = Path(self.td.name) / "notify.db"
        initialize(self.db)
        self.s = Settings("127.0.0.1", 5000, None, self.db, None, False, 1000, 100, 2, .05, 50, "INFO")
        self.w = BatchWriter(self.db, batch_size=1, flush_seconds=.02)
        self.w.start()
        self.addCleanup(self.w.shutdown)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._saved)

    def client(self, notifier=None):
        return create_app(self.s, self.w, None, notifier).test_client()

    def test_reports_inactive_without_notifier(self):
        r = self.client().get("/api/notifications")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json["active"])

    def test_reports_live_delivery_metrics(self):
        os.environ["TELEGRAM_BOT_TOKEN"] = "123:SECRET-VALUE"
        os.environ["TELEGRAM_CHAT_ID"] = "987654321"
        notifier = AlertNotifier(
            NotifierConfig(telegram_token="123:SECRET-VALUE", telegram_chat_id="987654321"),
            transport=lambda *a: (200, ""),
        )
        notifier.start()
        self.addCleanup(notifier.shutdown, 2)
        r = self.client(notifier).get("/api/notifications")
        self.assertTrue(r.json["active"])
        self.assertTrue(r.json["telegram_configured"])
        self.assertEqual(r.json["min_severity"], "HIGH")
        self.assertIn("telegram", r.json["channels"])
        self.assertNotIn("SECRET-VALUE", r.get_data(as_text=True))

    def test_status_endpoint_includes_notifications(self):
        r = self.client().get("/api/status")
        self.assertEqual(r.status_code, 200)
        self.assertIn("notifications", r.json)

    def test_telegram_endpoint_keeps_legacy_shape(self):
        os.environ["TELEGRAM_BOT_TOKEN"] = "123:SECRET-VALUE"
        os.environ["TELEGRAM_CHAT_ID"] = "987654321"
        r = self.client().get("/api/telegram")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json["configured"])
        self.assertEqual(r.json["chat_id"], "••••4321")
        self.assertNotIn("SECRET-VALUE", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
