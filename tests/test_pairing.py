"""Tests for Telegram chat pairing.

Most of these are security tests rather than behaviour tests. Pairing is the
one place where an outside party -- anyone who can message the bot -- gets to
influence stored state, so each documented attack gets an explicit case:
replay, expiry bypass, cross-user linking, chat-id injection, and guessing.
"""

from __future__ import annotations

import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from nemos.database import initialize
from nemos.pairing import (
    MAX_AUDIT,
    MAX_CODES,
    PairingStore,
    hash_code,
    valid_chat_id,
    valid_code_shape,
)

CHAT = "1000000001"
OTHER_CHAT = "-1001234567890"


class PairingTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = Path(self.dir.name) / "nemos.db"
        initialize(self.db)
        self.store = PairingStore(self.db)

    def rows(self, query: str, *params):
        c = sqlite3.connect(self.db)
        try:
            return c.execute(query, params).fetchall()
        finally:
            c.close()


class CodeTests(PairingTestCase):
    def test_a_fresh_code_links_the_chat_that_redeems_it(self):
        code, _ = self.store.issue()
        ok, reason = self.store.redeem(code, CHAT)
        self.assertTrue(ok, reason)
        self.assertEqual(self.store.chat_ids(), [CHAT])
        self.assertTrue(self.store.is_linked(CHAT))

    def test_codes_are_unpredictable_and_never_repeat(self):
        codes = {self.store.issue()[0] for _ in range(50)}
        self.assertEqual(len(codes), 50)
        for code in codes:
            # secrets.token_urlsafe(16) -> 22 characters of url-safe base64.
            self.assertGreaterEqual(len(code), 20)
            self.assertTrue(valid_code_shape(code))

    def test_the_plaintext_code_is_never_stored(self):
        code, _ = self.store.issue()
        stored = self.rows("SELECT code_hash FROM telegram_pairings")
        self.assertEqual(len(stored), 1)
        self.assertNotEqual(stored[0][0], code)
        self.assertEqual(stored[0][0], hash_code(code))
        # And nothing anywhere in the database holds it verbatim.
        blob = Path(self.db).read_bytes()
        self.assertNotIn(code.encode(), blob)

    def test_pending_describes_the_code_without_revealing_it(self):
        code, expires = self.store.issue()
        pending = self.store.pending()
        assert pending is not None
        self.assertAlmostEqual(pending["expires_at"], expires, places=3)
        self.assertGreater(pending["expires_in"], 0)
        self.assertNotIn(code, repr(pending))

    def test_issuing_retires_the_previous_code(self):
        """Two live codes means a link screenshotted earlier still works."""
        first, _ = self.store.issue()
        second, _ = self.store.issue()
        self.assertFalse(self.store.redeem(first, CHAT)[0])
        self.assertTrue(self.store.redeem(second, CHAT)[0])

    def test_revoke_kills_the_outstanding_code(self):
        code, _ = self.store.issue()
        self.assertEqual(self.store.revoke(), 1)
        self.assertIsNone(self.store.pending())
        self.assertFalse(self.store.redeem(code, CHAT)[0])

    def test_stored_codes_stay_bounded(self):
        for _ in range(MAX_CODES + 20):
            code, _ = self.store.issue()
            self.store.redeem(code, CHAT)
        count = self.rows("SELECT COUNT(*) FROM telegram_pairings")[0][0]
        self.assertLessEqual(count, MAX_CODES)


class AttackTests(PairingTestCase):
    def test_a_code_cannot_be_replayed(self):
        code, _ = self.store.issue()
        self.assertTrue(self.store.redeem(code, CHAT)[0])
        ok, reason = self.store.redeem(code, CHAT)
        self.assertFalse(ok)
        self.assertEqual(reason, "used")

    def test_a_replay_cannot_link_a_different_chat(self):
        """The cross-user case: someone else scanning a used link."""
        code, _ = self.store.issue()
        self.store.redeem(code, CHAT)
        ok, _ = self.store.redeem(code, OTHER_CHAT)
        self.assertFalse(ok)
        self.assertEqual(self.store.chat_ids(), [CHAT])

    def test_an_expired_code_is_refused(self):
        code, _ = self.store.issue(now=1000.0)
        ok, reason = self.store.redeem(code, CHAT, now=1000.0 + self.store.ttl + 1)
        self.assertFalse(ok)
        self.assertEqual(reason, "expired")
        self.assertEqual(self.store.chat_ids(), [])

    def test_expiry_is_measured_against_the_server_clock(self):
        """Nothing the caller supplies can extend a code's life."""
        code, _ = self.store.issue(now=1000.0)
        self.assertTrue(self.store.redeem(code, CHAT, now=1000.0 + 1)[0])

    def test_an_expired_code_is_invisible_to_pending(self):
        self.store.issue(now=1000.0)
        self.assertIsNone(self.store.pending(now=1000.0 + 10_000))

    def test_a_guessed_code_is_refused(self):
        self.store.issue()
        for guess in ("A" * 22, "nemos-pairing-code-000", "0" * 32):
            with self.subTest(guess=guess):
                self.assertFalse(self.store.redeem(guess, CHAT)[0])
        self.assertEqual(self.store.chat_ids(), [])

    def test_only_telegram_shaped_chat_ids_are_accepted(self):
        """Chat-id injection: the value must look like one Telegram issued."""
        code, _ = self.store.issue()
        for bad in ("../../etc/passwd", "1; DROP TABLE alerts", "abc",
                    "", "1" * 40, "12 34", None, {"id": 1}):
            with self.subTest(chat=bad):
                self.assertFalse(valid_chat_id(bad))
                ok, reason = self.store.redeem(code, bad)
                self.assertFalse(ok)
                self.assertEqual(reason, "invalid")
        # The code survives every rejection and still works for a real chat.
        self.assertTrue(self.store.redeem(code, CHAT)[0])

    def test_negative_group_chat_ids_are_accepted(self):
        self.assertTrue(valid_chat_id(OTHER_CHAT))
        code, _ = self.store.issue()
        self.assertTrue(self.store.redeem(code, OTHER_CHAT)[0])

    def test_a_malformed_code_never_reaches_the_database(self):
        for bad in (None, 12345, "short", "x" * 100, "has spaces in it here",
                    "semi;colon;separated;value"):
            with self.subTest(code=bad):
                self.assertFalse(valid_code_shape(bad))
                self.assertEqual(self.store.redeem(bad, CHAT), (False, "invalid"))

    def test_concurrent_redemptions_of_one_code_produce_one_link(self):
        """The replay guard has to hold under a race, not only in sequence."""
        code, _ = self.store.issue()
        results: list[tuple[bool, str]] = []
        lock = threading.Lock()
        barrier = threading.Barrier(6)

        def attempt(chat: str) -> None:
            barrier.wait()
            outcome = self.store.redeem(code, chat)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=attempt, args=(str(1000 + i),))
                   for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(sum(1 for ok, _ in results if ok), 1, results)
        self.assertEqual(len(self.store.chat_ids()), 1)

    def test_an_unknown_chat_is_not_authorised(self):
        self.assertFalse(self.store.is_linked("999"))
        self.assertFalse(self.store.is_linked("../admin"))


class LinkTests(PairingTestCase):
    def test_links_record_a_label_and_timestamps(self):
        code, _ = self.store.issue()
        self.store.redeem(code, CHAT, label="analyst", now=1234.0)
        links = self.store.links()
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["chat_id"], CHAT)
        self.assertEqual(links[0]["label"], "analyst")
        self.assertEqual(links[0]["linked_at"], 1234.0)

    def test_a_label_is_bounded(self):
        code, _ = self.store.issue()
        self.store.redeem(code, CHAT, label="x" * 500)
        self.assertLessEqual(len(self.store.links()[0]["label"]), 64)

    def test_unlink_removes_the_audience_entry(self):
        code, _ = self.store.issue()
        self.store.redeem(code, CHAT)
        self.assertTrue(self.store.unlink(CHAT))
        self.assertEqual(self.store.chat_ids(), [])
        self.assertFalse(self.store.unlink(CHAT))

    def test_unlink_rejects_a_malformed_chat_id(self):
        self.assertFalse(self.store.unlink("'; DELETE FROM telegram_links; --"))

    def test_relinking_the_same_chat_does_not_duplicate_it(self):
        for _ in range(3):
            code, _ = self.store.issue()
            self.store.redeem(code, CHAT)
        self.assertEqual(self.store.chat_ids(), [CHAT])

    def test_touch_updates_last_seen_for_a_linked_chat_only(self):
        code, _ = self.store.issue()
        self.store.redeem(code, CHAT, now=100.0)
        self.store.touch(CHAT, now=500.0)
        self.assertEqual(self.store.links()[0]["last_seen"], 500.0)
        self.store.touch("nonsense", now=900.0)
        self.assertEqual(self.store.links()[0]["last_seen"], 500.0)

    def test_a_store_survives_a_restart(self):
        code, _ = self.store.issue()
        self.store.redeem(code, CHAT)
        self.assertEqual(PairingStore(self.db).chat_ids(), [CHAT])


class AuditTests(PairingTestCase):
    def test_actions_are_recorded_with_actor_target_and_result(self):
        self.store.record(CHAT, "acknowledge", "NEMOS-ABCDEF012345", "ok", "1 detection")
        entry = self.store.audit()[0]
        self.assertEqual(entry["actor"], CHAT)
        self.assertEqual(entry["action"], "acknowledge")
        self.assertEqual(entry["target"], "NEMOS-ABCDEF012345")
        self.assertEqual(entry["result"], "ok")

    def test_the_newest_entry_comes_first(self):
        for i in range(5):
            self.store.record(CHAT, f"action{i}")
        self.assertEqual([e["action"] for e in self.store.audit(3)],
                         ["action4", "action3", "action2"])

    def test_the_audit_log_stays_bounded(self):
        for i in range(MAX_AUDIT + 50):
            self.store.record(CHAT, "ping", str(i))
        count = self.rows("SELECT COUNT(*) FROM telegram_audit")[0][0]
        self.assertLessEqual(count, MAX_AUDIT)

    def test_fields_are_truncated_rather_than_stored_whole(self):
        self.store.record("x" * 200, "y" * 200, "z" * 200, "w" * 200, "v" * 500)
        entry = self.store.audit()[0]
        self.assertLessEqual(len(entry["actor"]), 32)
        self.assertLessEqual(len(entry["action"]), 48)
        self.assertLessEqual(len(entry["detail"]), 200)

    def test_a_recording_failure_never_raises(self):
        """An audit write must not be able to kill the thread it describes."""
        broken = PairingStore(self.db)
        broken.db_path = Path(self.dir.name) / "no-such-dir" / "x" / "y.db"
        try:
            broken.record(CHAT, "acknowledge")
        except Exception as exc:  # pragma: no cover - the assertion is the point
            self.fail(f"record() raised {exc!r}")

    def test_pairing_outcomes_are_audited_without_the_code(self):
        code, _ = self.store.issue()
        self.store.redeem(code, CHAT)
        self.store.record(CHAT, "pair", "", "ok", "")
        for entry in self.store.audit():
            self.assertNotIn(code, str(entry))


class TtlTests(PairingTestCase):
    def test_the_ttl_is_clamped_to_a_sane_range(self):
        self.assertEqual(PairingStore(self.db, ttl=0.0).ttl, 30.0)
        self.assertEqual(PairingStore(self.db, ttl=999_999.0).ttl, 3600.0)
        self.assertEqual(PairingStore(self.db, ttl=120.0).ttl, 120.0)

    def test_the_default_window_is_short(self):
        store = PairingStore(self.db)
        _, expires = store.issue()
        self.assertLessEqual(expires - time.time(), 301.0)


if __name__ == "__main__":
    unittest.main()
