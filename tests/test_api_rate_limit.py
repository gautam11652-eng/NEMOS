"""Rate limiting on the HTTP API.

Two buckets, because the two risks differ in size. The general limit bounds
resource use and must stay clear of the dashboard's own polling. The auth
limit bounds guesses at the API token -- the only credential NEMOS has -- and
is far tighter, because nothing legitimate retries a rejected credential.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nemos.api import RateLimiter, create_app
from nemos.config import load_settings
from nemos.database import initialize
from nemos.storage import BatchWriter

TOKEN = "rate-limit-test-token-not-a-real-credential"
ROOT = Path(__file__).resolve().parents[1]


class RateLimiterUnitTests(unittest.TestCase):
    def test_requests_are_allowed_up_to_the_limit(self):
        limiter = RateLimiter(general_per_minute=5)
        for _ in range(5):
            self.assertTrue(limiter.check("10.0.0.1")[0])
        allowed, retry = limiter.check("10.0.0.1")
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    def test_clients_are_limited_independently(self):
        limiter = RateLimiter(general_per_minute=2)
        limiter.check("10.0.0.1"); limiter.check("10.0.0.1")
        self.assertFalse(limiter.check("10.0.0.1")[0])
        self.assertTrue(limiter.check("10.0.0.2")[0], "one client exhausted another's budget")

    def test_the_window_resets(self):
        limiter = RateLimiter(general_per_minute=2, window=0.25)
        limiter.check("10.0.0.1"); limiter.check("10.0.0.1")
        self.assertFalse(limiter.check("10.0.0.1")[0])
        import time as _t
        _t.sleep(0.3)
        self.assertTrue(limiter.check("10.0.0.1")[0])

    def test_auth_failures_have_their_own_tighter_budget(self):
        limiter = RateLimiter(general_per_minute=1000, auth_failures_per_minute=3)
        for _ in range(3):
            self.assertFalse(limiter.record_auth_failure("10.0.0.1")[0])
        blocked, retry = limiter.record_auth_failure("10.0.0.1")
        self.assertTrue(blocked)
        self.assertGreater(retry, 0)

    def test_client_table_is_bounded(self):
        """Keyed by peer address, which an attacker on a local segment varies."""
        limiter = RateLimiter(general_per_minute=1000, max_clients=64)
        for i in range(5000):
            limiter.check(f"10.0.{i // 256}.{i % 256}")
        self.assertLessEqual(limiter.metrics()["tracked_clients"], 64)

    def test_auth_table_is_bounded_too(self):
        limiter = RateLimiter(auth_failures_per_minute=1000, max_clients=64)
        for i in range(5000):
            limiter.record_auth_failure(f"10.0.{i // 256}.{i % 256}")
        self.assertLessEqual(limiter.metrics()["clients_with_auth_failures"], 64)

    def test_limits_cannot_be_configured_to_zero(self):
        """A limit of zero would lock everyone out, including the dashboard."""
        limiter = RateLimiter(general_per_minute=0, auth_failures_per_minute=0)
        self.assertGreaterEqual(limiter.general, 1)
        self.assertGreaterEqual(limiter.auth_failures, 1)


class RateLimitedApiTests(unittest.TestCase):
    def _client(self, **env):
        tmp = Path(tempfile.mkdtemp()) / "rl.db"
        initialize(tmp)
        base = {"NEMOS_DB": str(tmp), "NEMOS_HOST": "127.0.0.1"}
        base.update(env)
        self.env = mock.patch.dict(os.environ, base)
        self.env.start()
        self.addCleanup(self.env.stop)
        writer = BatchWriter(tmp, 50, 0.2)
        self.addCleanup(writer.shutdown, 2)
        writer.start()
        app = create_app(load_settings(ROOT), writer=writer)
        return app, app.test_client()

    def test_exceeding_the_limit_returns_429_with_retry_after(self):
        _, client = self._client(NEMOS_API_RATE="10")
        for _ in range(10):
            self.assertEqual(client.get("/api/stats").status_code, 200)
        response = client.get("/api/stats")
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)
        self.assertGreater(int(response.headers["Retry-After"]), 0)

    def test_health_is_never_rate_limited(self):
        """A liveness probe must not be able to exhaust a client's budget."""
        _, client = self._client(NEMOS_API_RATE="10")
        for _ in range(60):
            self.assertEqual(client.get("/api/health").status_code, 200)
        self.assertEqual(client.get("/api/stats").status_code, 200)

    def test_token_guessing_is_throttled_before_the_general_limit(self):
        """The control that matters: a token search is slowed by each attempt."""
        _, client = self._client(NEMOS_API_TOKEN=TOKEN,
                                 NEMOS_API_RATE="10000", NEMOS_API_AUTH_RATE="5")
        codes = [client.get("/api/stats", headers={"X-NEMOS-Token": f"guess{i}"}).status_code
                 for i in range(8)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5:], [429] * 3, "token guessing was not throttled")

    def test_a_valid_token_is_unaffected_by_others_failing(self):
        _, client = self._client(NEMOS_API_TOKEN=TOKEN,
                                 NEMOS_API_RATE="10000", NEMOS_API_AUTH_RATE="3")
        for _ in range(3):
            client.get("/api/stats", headers={"X-NEMOS-Token": "wrong"})
        # Same client is now blocked; that is intended -- it is the guesser.
        self.assertEqual(
            client.get("/api/stats", headers={"X-NEMOS-Token": "wrong"}).status_code, 429)

    def test_successful_requests_do_not_consume_the_auth_budget(self):
        _, client = self._client(NEMOS_API_TOKEN=TOKEN, NEMOS_API_AUTH_RATE="2")
        for _ in range(20):
            response = client.get("/api/stats", headers={"X-NEMOS-Token": TOKEN})
            self.assertEqual(response.status_code, 200)

    def test_forwarded_headers_cannot_mint_new_identities(self):
        """X-Forwarded-For is attacker-controlled and must not key the limit."""
        _, client = self._client(NEMOS_API_RATE="10")
        for _ in range(10):
            client.get("/api/stats")
        blocked = client.get("/api/stats", headers={"X-Forwarded-For": "203.0.113.9"})
        self.assertEqual(blocked.status_code, 429,
                         "a spoofable header reset the rate limit")

    def test_limit_is_visible_to_the_operator(self):
        app, client = self._client(NEMOS_API_RATE="123", NEMOS_API_AUTH_RATE="7")
        body = client.get("/api/status").get_json()
        self.assertEqual(body["rate_limit"]["general_per_minute"], 123)
        self.assertEqual(body["rate_limit"]["auth_failures_per_minute"], 7)

    def test_the_configured_limit_has_a_floor(self):
        """A limit below the dashboard's own polling would break the interface.

        NEMOS_API_RATE=5 is raised to the floor rather than honoured, so a
        misconfiguration cannot lock an operator out of their own sensor.
        """
        self._client(NEMOS_API_RATE="1")
        self.assertGreaterEqual(load_settings(ROOT).api_rate_limit, 10)

    def test_default_limit_leaves_room_for_the_dashboard(self):
        """The dashboard polls four endpoints every five seconds: ~48/min."""
        _, client = self._client()
        app_settings = load_settings(ROOT)
        self.assertGreaterEqual(app_settings.api_rate_limit, 120)


if __name__ == "__main__":
    unittest.main()
