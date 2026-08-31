"""Authentication contract tests.

These exist because the dashboard rewrite shipped a token field that could
never work: the script sent `Authorization: Bearer` while the API only read
`X-NEMOS-Token`. Every request returned 401, which looks like a wrong
credential rather than a wrong header name. Nothing in the suite caught it,
because no test made an authenticated request the way the browser does.
"""

import re
import tempfile
import unittest
from pathlib import Path

from nemos.api import create_app
from nemos.config import load_settings
from nemos.database import initialize

TOKEN = "unit-test-token-not-a-real-credential"


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()) / "auth.db"
        initialize(self.tmp)
        import os
        from unittest import mock
        self.env = mock.patch.dict(os.environ, {
            "NEMOS_API_TOKEN": TOKEN,
            "NEMOS_DB": str(self.tmp),
            "NEMOS_HOST": "127.0.0.1",
        })
        self.env.start()
        settings = load_settings(Path(__file__).resolve().parents[1])
        self.app = create_app(settings, writer=None)
        self.client = self.app.test_client()

    def tearDown(self):
        self.env.stop()

    def test_nemos_header_is_accepted(self):
        self.assertEqual(self.client.get("/api/alerts", headers={"X-NEMOS-Token": TOKEN}).status_code, 200)

    def test_bearer_token_is_accepted(self):
        """What curl, scripts and most HTTP clients send by default."""
        self.assertEqual(
            self.client.get("/api/alerts", headers={"Authorization": f"Bearer {TOKEN}"}).status_code, 200)

    def test_bearer_scheme_is_case_insensitive(self):
        self.assertEqual(
            self.client.get("/api/alerts", headers={"Authorization": f"bearer {TOKEN}"}).status_code, 200)

    def test_missing_credential_is_rejected(self):
        self.assertEqual(self.client.get("/api/alerts").status_code, 401)

    def test_wrong_credential_is_rejected(self):
        self.assertEqual(self.client.get("/api/alerts", headers={"X-NEMOS-Token": "wrong"}).status_code, 401)
        self.assertEqual(
            self.client.get("/api/alerts", headers={"Authorization": "Bearer wrong"}).status_code, 401)

    def test_other_authorization_schemes_are_rejected(self):
        self.assertEqual(
            self.client.get("/api/alerts", headers={"Authorization": f"Basic {TOKEN}"}).status_code, 401)

    def test_empty_header_is_rejected(self):
        self.assertEqual(self.client.get("/api/alerts", headers={"X-NEMOS-Token": ""}).status_code, 401)

    def test_health_stays_reachable_for_liveness_probes(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_no_credential_is_echoed_in_the_rejection(self):
        response = self.client.get("/api/alerts", headers={"X-NEMOS-Token": "wrong"})
        self.assertNotIn(TOKEN, response.get_data(as_text=True))
        self.assertNotIn("wrong", response.get_data(as_text=True))


class DashboardAuthContractTests(unittest.TestCase):
    """The browser must send a header the server actually reads."""

    def test_dashboard_sends_a_header_the_api_checks(self):
        root = Path(__file__).resolve().parents[1]
        js = (root / "nemos" / "static" / "app.js").read_text()
        api = (root / "nemos" / "api.py").read_text()

        sent = set(re.findall(r'headers\["([A-Za-z-]+)"\]', js))
        sent |= {"Authorization"} if "headers.Authorization" in js else set()
        self.assertTrue(sent, "the dashboard sends no auth header at all")

        read = set(re.findall(r'request\.headers\.get\("([A-Za-z-]+)"', api))
        self.assertTrue(sent & read,
                        f"dashboard sends {sorted(sent)} but the API only reads {sorted(read)}")


if __name__ == "__main__":
    unittest.main()
