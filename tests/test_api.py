import tempfile
import time
import unittest
from pathlib import Path

from nemos.api import create_app
from nemos.config import Settings
from nemos.database import initialize
from nemos.storage import BatchWriter


def wait_for(predicate, timeout=10.0, interval=0.01):
    """Poll until ``predicate()`` returns a truthy value, then return it.

    The BatchWriter flushes on a background thread, so a fixed sleep is a guess
    rather than a synchronization point: on a loaded CI runner the write can
    land after the sleep expires, producing a spurious failure. Polling is both
    deterministic and usually faster than the sleep it replaces.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return predicate()


class APITests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        db = Path(self.td.name) / "api.db"
        initialize(db)
        self.s = Settings("127.0.0.1", 5000, None, db, None, False, 1000, 100, 2, .05, 50, "INFO")
        self.w = BatchWriter(db, batch_size=1, flush_seconds=.02)
        self.w.start()
        self.client = create_app(self.s, self.w).test_client()

    def tearDown(self):
        self.w.shutdown()
        self.td.cleanup()

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["status"], "online")
        from nemos.version import VERSION
        self.assertEqual(r.json["version"], VERSION)

    def test_bad_packet(self):
        self.assertEqual(self.client.post("/api/packet", json=[]).status_code, 400)

    def test_dashboard(self):
        r = self.client.get("/api/dashboard")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["stats"]["packets"], 0)

    def test_telegram_status_does_not_expose_token(self):
        import os
        old_token, old_chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
        try:
            os.environ["TELEGRAM_BOT_TOKEN"] = "super-secret-token"
            os.environ["TELEGRAM_CHAT_ID"] = "123456789"
            r = self.client.get("/api/telegram")
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json["configured"])
            self.assertEqual(r.json["chat_id"], "••••6789")
            self.assertNotIn("super-secret-token", r.get_data(as_text=True))
        finally:
            if old_token is None: os.environ.pop("TELEGRAM_BOT_TOKEN", None)
            else: os.environ["TELEGRAM_BOT_TOKEN"] = old_token
            if old_chat is None: os.environ.pop("TELEGRAM_CHAT_ID", None)
            else: os.environ["TELEGRAM_CHAT_ID"] = old_chat

    def test_techniques_endpoint_exposes_conservative_attack_catalog(self):
        r = self.client.get("/api/techniques")
        self.assertEqual(r.status_code, 200)
        ids = {item["technique_id"] for item in r.json["techniques"]}
        self.assertIn("T1046", ids)
        self.assertIn("T1071.004", ids)
        self.assertIn("T1498.001", ids)
        self.assertIn("T1557.002", ids)
        self.assertTrue(all(item["mapped"] for item in r.json["techniques"]))

    def test_status_reports_capture_disabled(self):
        r = self.client.get("/api/status")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["capture"]["state"], "not_configured")
        self.assertEqual(r.json["capture"]["interface"], "default")
        self.assertIn("queue_depth", r.json["writer"])


    def test_packet_defaults_missing_timestamp(self):
        r = self.client.post("/api/packet", json={
            "source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "TCP",
            "destination_port": 443,
        })
        self.assertEqual(r.status_code, 202)

    def test_local_cross_site_mutation_is_blocked(self):
        r = self.client.post(
            "/api/packet",
            json={"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "TCP"},
            headers={"Origin": "https://attacker.invalid", "Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(r.status_code, 403)

    def test_security_headers(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])

    def test_dashboard_conditional_request(self):
        first = self.client.get("/api/dashboard")
        self.assertEqual(first.status_code, 200)
        etag = first.headers.get("ETag")
        self.assertTrue(etag)
        second = self.client.get("/api/dashboard", headers={"If-None-Match": etag})
        self.assertEqual(second.status_code, 304)

    def test_dashboard_etag_changes_after_telemetry_write(self):
        first = self.client.get("/api/dashboard")
        etag = first.headers["ETag"]
        self.assertEqual(self.client.post("/api/packet", json={
            "source":"10.0.0.1", "destination":"10.0.0.2", "protocol":"DNS", "destination_port":53
        }).status_code, 202)
        def dns_counted():
            response = self.client.get("/api/dashboard")
            return response if response.json["stats"]["dns"] == 1 else None

        second = wait_for(dns_counted)
        self.assertNotEqual(second.headers["ETag"], etag)
        self.assertEqual(second.json["stats"]["dns"], 1)

    def test_dashboard_host_summary_uses_materialized_stats(self):
        self.client.post("/api/packet", json={
            "source":"10.0.0.10", "destination":"10.0.0.20", "protocol":"TCP"
        })
        def host_recorded():
            response = self.client.get("/api/dashboard")
            hosts = {h["host"]: h for h in response.json["hosts"]}
            return (response, hosts) if "10.0.0.10" in hosts else None

        r, hosts = wait_for(host_recorded)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(hosts["10.0.0.10"]["packets"], 1)
        self.assertEqual(hosts["10.0.0.20"]["packets"], 1)

    def test_hosts_endpoint_uses_materialized_stats(self):
        self.client.post("/api/packet", json={
            "source":"10.0.0.30", "destination":"10.0.0.40", "protocol":"DNS",
            "destination_port":53, "packet_size":90,
        })
        def host_indexed():
            response = self.client.get("/api/hosts?limit=1")
            return response if response.json else None

        r = wait_for(host_indexed)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json), 1)
        self.assertEqual(r.json[0]["host"], "10.0.0.30")
        self.assertEqual(r.json[0]["packets"], 1)


    def test_dashboard_etag_tracks_capture_state_changes(self):
        class FakeCapture:
            def __init__(self):
                self.state = {
                    "state": "running", "running": True, "interface": "eth0",
                    "packets_seen": 10, "last_packet": "t", "error": None,
                }
            def status(self):
                return dict(self.state)

        capture = FakeCapture()
        client = create_app(self.s, self.w, capture).test_client()
        first = client.get("/api/dashboard")
        self.assertEqual(first.status_code, 200)
        etag = first.headers["ETag"]

        capture.state.update(state="error", running=False, error="capture failed")
        second = client.get("/api/dashboard", headers={"If-None-Match": etag})
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json["capture"]["state"], "error")
        self.assertEqual(second.json["capture"]["error"], "capture failed")




class AuthAndValidationTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        db = Path(self.td.name) / "secure.db"
        initialize(db)
        self.s = Settings("127.0.0.1", 5000, None, db, "secret-token", False, 1000, 100, 2, .02, 50, "INFO")
        self.w = BatchWriter(db, batch_size=1, flush_seconds=.02)
        self.w.start()
        self.client = create_app(self.s, self.w).test_client()

    def tearDown(self):
        self.w.shutdown()
        self.td.cleanup()

    def test_get_api_requires_token(self):
        self.assertEqual(self.client.get("/api/stats").status_code, 401)
        self.assertEqual(
            self.client.get("/api/stats", headers={"X-NEMOS-Token": "secret-token"}).status_code,
            200,
        )
        self.assertEqual(self.client.get("/api/health").status_code, 200)


    def test_metrics_requires_token_and_reports_writer_state(self):
        self.assertEqual(self.client.get("/api/metrics").status_code, 401)
        r = self.client.get("/api/metrics", headers={"X-NEMOS-Token": "secret-token"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("queue_depth", r.json["writer"])

    def test_packet_validation(self):
        headers = {"X-NEMOS-Token": "secret-token"}
        bad = {"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "TCP", "destination_port": 70000}
        self.assertEqual(self.client.post("/api/packet", json=bad, headers=headers).status_code, 400)
        bad["destination_port"] = 443
        bad["source"] = "not-ip"
        self.assertEqual(self.client.post("/api/packet", json=bad, headers=headers).status_code, 400)

        bad["source"] = "10.0.0.1"
        bad["destination_port"] = 443.5
        self.assertEqual(self.client.post("/api/packet", json=bad, headers=headers).status_code, 400)

        bad["destination_port"] = 443
        bad["packet_size"] = 64.5
        self.assertEqual(self.client.post("/api/packet", json=bad, headers=headers).status_code, 400)


class HostIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        db = Path(self.td.name) / "hosts.db"
        initialize(db)
        self.s = Settings("127.0.0.1", 5000, None, db, None, False, 1000, 100, 2, .02, 50, "INFO")
        self.w = BatchWriter(db, batch_size=1, flush_seconds=.01)
        self.w.start()
        self.client = create_app(self.s, self.w).test_client()
        self.client.post("/api/packet", json={"source":"10.0.0.10","destination":"10.0.0.20","protocol":"TCP","destination_port":443,"packet_size":100})
        self.w.submit_alert(__import__('nemos.models', fromlist=['Alert']).Alert(
            "2026-01-01T00:00:00+00:00","PORT_SCAN","NETWORK_RECONNAISSANCE","10.0.0.10","HIGH",80,90,"test",technique="T1046",incident_id="NEMOS-TEST123456",evidence={}
        ))
        # Both the packet and the alert must reach SQLite before any test in
        # this class runs; the writer flushes them asynchronously.
        wait_for(lambda: self.client.get("/api/hosts").json or None)
        wait_for(lambda: self.client.get("/api/incidents/NEMOS-TEST123456").status_code == 200)

    def tearDown(self):
        self.w.shutdown(); self.td.cleanup()

    def test_hosts(self):
        r=self.client.get('/api/hosts')
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json[0]['host'],'10.0.0.10')
        self.assertGreaterEqual(r.json[0]['risk_score'],80)

    def test_incident_detail(self):
        r=self.client.get('/api/incidents/NEMOS-TEST123456')
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json['incident_id'],'NEMOS-TEST123456')
        self.assertEqual(len(r.json['alerts']),1)

if __name__ == "__main__":
    unittest.main()
