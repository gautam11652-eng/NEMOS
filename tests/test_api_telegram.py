"""Tests for the Telegram pairing endpoints.

The single most important property: no response from any of these routes, in
any state, contains the bot token. Everything else -- the QR, the countdown,
the linked-chat list -- is a convenience layered on top of that.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nemos.api import create_app
from nemos.config import Settings
from nemos.database import initialize
from nemos.pairing import PairingStore
from nemos.storage import BatchWriter

TOKEN = "1234567890:AAxxFAKE-not-a-real-bot-token-value"  # noqa: S105
USERNAME = "nemos_sentinel_bot"
CHAT = "1000000001"


class TelegramApiTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.db = Path(self.td.name) / "api.db"
        initialize(self.db)
        self.settings = Settings("127.0.0.1", 5000, None, self.db, None, False,
                                 1000, 100, 2, .05, 50, "INFO")
        self.writer = BatchWriter(self.db, batch_size=1, flush_seconds=.02)
        self.writer.start()
        self.addCleanup(self.writer.shutdown)
        self.store = PairingStore(self.db)
        self.app = create_app(self.settings, self.writer, pairing=self.store)
        self.client = self.app.test_client()
        self.env = patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": TOKEN,
            "TELEGRAM_BOT_USERNAME": USERNAME,
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def link(self, chat_id=CHAT):
        code, _ = self.store.issue()
        self.store.redeem(code, chat_id, label="analyst")


class StatusTests(TelegramApiTests):
    def test_pairing_is_available_when_the_deployment_is_configured(self):
        body = self.client.get("/api/telegram/pair").get_json()
        self.assertTrue(body["available"])
        self.assertEqual(body["bot_username"], USERNAME)
        self.assertFalse(body["connected"])

    def test_a_missing_token_is_reported_as_a_deployment_problem(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": ""}):
            body = self.client.get("/api/telegram/pair").get_json()
        self.assertFalse(body["available"])
        self.assertIn("TELEGRAM_BOT_TOKEN", body["error"])

    def test_a_missing_username_is_reported_separately(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": ""}):
            body = self.client.get("/api/telegram/pair").get_json()
        self.assertFalse(body["available"])
        self.assertIn("TELEGRAM_BOT_USERNAME", body["error"])

    def test_linked_chats_are_listed_with_the_id_masked(self):
        self.link()
        body = self.client.get("/api/telegram/pair").get_json()
        self.assertTrue(body["connected"])
        self.assertEqual(len(body["linked"]), 1)
        self.assertNotIn(CHAT, json.dumps(body))
        self.assertTrue(body["linked"][0]["chat_id"].endswith(CHAT[-4:]))

    def test_an_outstanding_code_is_reported_but_not_returned(self):
        code, _ = self.store.issue()
        body = self.client.get("/api/telegram/pair").get_json()
        self.assertIsNotNone(body["pending"])
        self.assertGreater(body["pending"]["expires_in"], 0)
        self.assertNotIn(code, json.dumps(body))


class CreateTests(TelegramApiTests):
    def test_a_pairing_request_returns_a_link_and_a_qr_code(self):
        body = self.client.post("/api/telegram/pair").get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["link"].startswith(f"https://t.me/{USERNAME}?start="))
        self.assertTrue(body["qr_svg"].startswith("<svg "))
        self.assertGreater(body["expires_in"], 0)

    def test_the_qr_encodes_the_link_and_nothing_executable(self):
        body = self.client.post("/api/telegram/pair").get_json()
        lowered = body["qr_svg"].lower()
        for forbidden in ("<script", "data:", "onload", "javascript:"):
            self.assertNotIn(forbidden, lowered, forbidden)

    def test_the_returned_code_actually_works_once(self):
        body = self.client.post("/api/telegram/pair").get_json()
        code = body["link"].split("start=", 1)[1]
        self.assertTrue(self.store.redeem(code, CHAT)[0])
        self.assertFalse(self.store.redeem(code, CHAT)[0])

    def test_a_second_request_invalidates_the_first_code(self):
        first = self.client.post("/api/telegram/pair").get_json()
        self.client.post("/api/telegram/pair")
        stale = first["link"].split("start=", 1)[1]
        self.assertFalse(self.store.redeem(stale, CHAT)[0])

    def test_pairing_is_refused_when_the_deployment_has_no_bot(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": ""}):
            response = self.client.post("/api/telegram/pair")
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.get_json()["ok"])

    def test_revoking_kills_the_outstanding_code(self):
        body = self.client.post("/api/telegram/pair").get_json()
        code = body["link"].split("start=", 1)[1]
        self.assertTrue(self.client.delete("/api/telegram/pair").get_json()["ok"])
        self.assertFalse(self.store.redeem(code, CHAT)[0])


class SecretTests(TelegramApiTests):
    def test_no_telegram_route_ever_returns_the_token(self):
        self.link()
        self.client.post("/api/telegram/pair")
        for method, path in (("get", "/api/telegram/pair"),
                             ("post", "/api/telegram/pair"),
                             ("get", "/api/telegram/audit"),
                             ("get", "/api/telegram"),
                             ("get", "/api/status"),
                             ("get", "/api/notifications")):
            with self.subTest(path=path, method=method):
                response = getattr(self.client, method)(path)
                body = response.get_data(as_text=True)
                self.assertNotIn(TOKEN, body)
                # Not even the secret half of it.
                self.assertNotIn(TOKEN.split(":", 1)[1], body)

    def test_the_page_itself_never_carries_the_token(self):
        page = self.client.get("/").get_data(as_text=True)
        self.assertNotIn(TOKEN, page)
        self.assertNotIn(TOKEN.split(":", 1)[1], page)

    def test_the_bot_username_is_public_and_may_appear(self):
        """It is in the t.me link a user scans; hiding it would break pairing."""
        body = self.client.get("/api/telegram/pair").get_json()
        self.assertEqual(body["bot_username"], USERNAME)


class LinkManagementTests(TelegramApiTests):
    def test_a_chat_can_be_unlinked(self):
        self.link()
        self.assertTrue(self.client.delete(f"/api/telegram/links/{CHAT}")
                        .get_json()["ok"])
        self.assertEqual(self.store.chat_ids(), [])

    def test_unlinking_an_unknown_chat_is_a_404(self):
        self.assertEqual(
            self.client.delete("/api/telegram/links/1234567").status_code, 404)

    def test_unlinking_is_audited(self):
        self.link()
        self.client.delete(f"/api/telegram/links/{CHAT}")
        entry = self.store.audit()[0]
        self.assertEqual(entry["action"], "unlink")
        self.assertEqual(entry["result"], "ok")

    def test_the_audit_trail_is_readable(self):
        self.store.record(CHAT, "acknowledge", "NEMOS-ABC123DEF456", "ok")
        entries = self.client.get("/api/telegram/audit").get_json()
        self.assertEqual(entries[0]["action"], "acknowledge")

    def test_the_audit_limit_is_bounded(self):
        for i in range(20):
            self.store.record(CHAT, "ping", str(i))
        entries = self.client.get("/api/telegram/audit?limit=99999").get_json()
        self.assertLessEqual(len(entries), 200)


class TestNotificationTests(TelegramApiTests):
    def test_it_refuses_when_no_chat_is_paired(self):
        response = self.client.post("/api/telegram/test")
        self.assertEqual(response.status_code, 409)
        self.assertIn("no Telegram chat", response.get_json()["error"])

    def test_it_refuses_when_the_deployment_has_no_token(self):
        self.link()
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": ""}):
            response = self.client.post("/api/telegram/test")
        self.assertEqual(response.status_code, 503)

    def test_it_sends_the_confirmation_to_every_paired_chat(self):
        self.link(CHAT)
        self.link("5550001111")
        sent = []

        def fake_api(token, method, params=None, timeout=15.0, api_base=""):
            sent.append(dict(params or {}))
            return {"message_id": 1}

        with patch("nemos.api.telegram_api", side_effect=fake_api):
            body = self.client.post("/api/telegram/test").get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["sent"], 2)
        self.assertEqual({p["chat_id"] for p in sent}, {CHAT, "5550001111"})
        self.assertIn("successfully connected", sent[0]["text"])

    def test_a_delivery_failure_is_reported_not_swallowed(self):
        self.link()
        with patch("nemos.api.telegram_api", side_effect=RuntimeError("chat not found")):
            response = self.client.post("/api/telegram/test")
        self.assertEqual(response.status_code, 502)
        self.assertIn("chat not found", response.get_json()["error"])

    def test_a_test_send_is_audited(self):
        self.link()
        with patch("nemos.api.telegram_api", return_value={"message_id": 1}):
            self.client.post("/api/telegram/test")
        entry = self.store.audit()[0]
        self.assertEqual(entry["action"], "test_notification")
        self.assertEqual(entry["result"], "ok")


class WithoutPairingStoreTests(unittest.TestCase):
    """The app must still start when it is created without a pairing store."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        db = Path(self.td.name) / "api.db"
        initialize(db)
        settings = Settings("127.0.0.1", 5000, None, db, None, False,
                            1000, 100, 2, .05, 50, "INFO")
        writer = BatchWriter(db, batch_size=1, flush_seconds=.02)
        writer.start()
        self.addCleanup(writer.shutdown)
        self.client = create_app(settings, writer).test_client()

    def test_status_reports_pairing_as_unavailable(self):
        body = self.client.get("/api/telegram/pair").get_json()
        self.assertFalse(body["available"])

    def test_mutating_routes_answer_503_rather_than_crashing(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": TOKEN,
                                     "TELEGRAM_BOT_USERNAME": USERNAME}):
            self.assertEqual(self.client.post("/api/telegram/pair").status_code, 503)
            self.assertEqual(self.client.delete("/api/telegram/pair").status_code, 503)
            self.assertEqual(
                self.client.delete(f"/api/telegram/links/{CHAT}").status_code, 503)

    def test_the_audit_endpoint_answers_empty(self):
        self.assertEqual(self.client.get("/api/telegram/audit").get_json(), [])


if __name__ == "__main__":
    unittest.main()
