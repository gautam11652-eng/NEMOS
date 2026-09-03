"""Tests for the Telegram command bot.

No network is touched: the Bot API is replaced with a recorder, so what is
asserted is exactly what NEMOS would have sent and to whom.

The properties under test are, in order of importance:

- an unlinked chat learns nothing about the network;
- a state-changing action is authorised, audited and recoverable;
- a bad update, a failing API or a hostile payload never kills the poller.
"""

from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from nemos.bot import (
    COMMAND_RATE,
    DailyBrief,
    TelegramBot,
    collect_brief,
    collect_critical,
    collect_hosts,
    collect_incident,
    collect_incidents,
    collect_status,
)
from nemos.database import connect, initialize
from nemos.pairing import PairingStore

CHAT = "1000000001"
STRANGER = "5550001111"
TOKEN = "test-token-value"  # noqa: S105 - a placeholder, not a credential
INCIDENT = "NEMOS-ABC123DEF456"
OTHER_INCIDENT = "NEMOS-999888777666"


class Recorder:
    """Stands in for nemos.notify.telegram_api."""

    def __init__(self, updates=None):
        self.calls: list[tuple[str, dict]] = []
        self.updates = list(updates or [])
        self.fail_with: Exception | None = None

    def __call__(self, token, method, params=None, timeout=15.0, api_base=""):
        self.calls.append((method, dict(params or {})))
        if self.fail_with is not None:
            raise self.fail_with
        if method == "getUpdates":
            batch, self.updates = self.updates, []
            return batch
        return {"message_id": len(self.calls)}

    def sent(self) -> list[dict]:
        return [params for method, params in self.calls if method == "sendMessage"]

    def texts(self) -> str:
        return "\n".join(str(p.get("text", "")) for p in self.sent())


def message(text, chat_id=CHAT, update_id=1, username="analyst"):
    return {
        "update_id": update_id,
        "message": {"chat": {"id": int(chat_id)}, "text": text,
                    "from": {"username": username}},
    }


def callback(data, chat_id=CHAT, update_id=1, callback_id="cb1"):
    return {
        "update_id": update_id,
        "callback_query": {"id": callback_id, "data": data,
                           "message": {"chat": {"id": int(chat_id)}}},
    }


class BotTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db = Path(self.dir.name) / "nemos.db"
        initialize(self.db)
        self.store = PairingStore(self.db)
        self.api = Recorder()
        self.bot = TelegramBot(TOKEN, self.store, self.db, api=self.api,
                               started_at=0.0)

    def link(self, chat_id=CHAT):
        code, _ = self.store.issue()
        ok, reason = self.store.redeem(code, chat_id)
        assert ok, reason

    def seed(self, rows=None):
        rows = rows if rows is not None else [
            ("2026-09-03T10:00:00+00:00", "PORT_SCAN", "NETWORK_RECONNAISSANCE",
             "192.0.2.10", "CRITICAL", 92, 94, "43 ports in 20s", "T1046", INCIDENT,
             json.dumps({"scan_type": "vertical"})),
            ("2026-09-03T10:00:20+00:00", "NETWORK_FANOUT", "NETWORK_DISCOVERY",
             "192.0.2.10", "HIGH", 78, 80, "14 destinations", "T1018", INCIDENT, "{}"),
            ("2026-09-03T09:00:00+00:00", "ICMP_SWEEP", "NETWORK_RECONNAISSANCE",
             "198.51.100.7", "MEDIUM", 60, 65, "9 destinations", "T1018",
             OTHER_INCIDENT, "{}"),
        ]
        c = connect(self.db)
        try:
            c.executemany(
                """INSERT INTO alerts(timestamp,threat,category,source,severity,
                       risk_score,confidence,reason,technique,incident_id,evidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""", rows)
            c.execute("UPDATE telemetry_stats SET packets=1234 WHERE id=1")
            c.execute("INSERT OR REPLACE INTO host_stats(host,packets,alert_count,"
                      "critical_count,max_risk) VALUES ('192.0.2.10',4210,2,1,92)")
            c.commit()
        finally:
            c.close()


class AuthorizationTests(BotTestCase):
    def test_an_unlinked_chat_gets_pairing_instructions_and_no_data(self):
        self.seed()
        self.bot.handle(message("/status"))
        text = self.api.texts()
        self.assertIn("not linked", text)
        for leak in ("192.0.2.10", "PORT_SCAN", INCIDENT, "1,234"):
            self.assertNotIn(leak, text, leak)

    def test_every_data_command_is_refused_to_an_unlinked_chat(self):
        self.seed()
        for command in ("/status", "/incidents", "/critical", "/hosts",
                        f"/incident {INCIDENT}", "/brief", "/help"):
            with self.subTest(command=command):
                self.api.calls.clear()
                self.bot.handle(message(command))
                self.assertIn("not linked", self.api.texts())

    def test_a_linked_chat_is_answered(self):
        self.link()
        self.seed()
        self.bot.handle(message("/status"))
        self.assertIn("NEMOS STATUS", self.api.texts())

    def test_unlinking_revokes_access_immediately(self):
        self.link()
        self.store.unlink(CHAT)
        self.bot.handle(message("/status"))
        self.assertIn("not linked", self.api.texts())

    def test_a_second_chat_cannot_read_another_sensors_data(self):
        self.link(CHAT)
        self.seed()
        self.bot.handle(message("/incidents", chat_id=STRANGER))
        self.assertIn("not linked", self.api.texts())

    def test_a_reply_goes_only_to_the_chat_that_asked(self):
        self.link()
        self.seed()
        self.bot.handle(message("/status"))
        self.assertEqual({p["chat_id"] for p in self.api.sent()}, {CHAT})


class PairingCommandTests(BotTestCase):
    def test_start_with_a_valid_code_links_the_chat(self):
        code, _ = self.store.issue()
        self.bot.handle(message(f"/start {code}"))
        self.assertIn("pairing complete", self.api.texts())
        self.assertEqual(self.store.chat_ids(), [CHAT])

    def test_start_with_a_bad_code_links_nothing_and_says_little(self):
        self.bot.handle(message("/start not-a-real-code-at-all"))
        self.assertEqual(self.store.chat_ids(), [])
        text = self.api.texts()
        self.assertIn("not valid", text)
        # The reply must not say which way it failed.
        for tell in ("expired", "already used", "unknown"):
            self.assertNotIn(tell, text.lower(), tell)

    def test_a_replayed_start_does_not_link_a_second_chat(self):
        code, _ = self.store.issue()
        self.bot.handle(message(f"/start {code}", chat_id=CHAT))
        self.bot.handle(message(f"/start {code}", chat_id=STRANGER, update_id=2))
        self.assertEqual(self.store.chat_ids(), [CHAT])

    def test_pairing_is_audited_without_the_code(self):
        code, _ = self.store.issue()
        self.bot.handle(message(f"/start {code}"))
        entries = self.store.audit()
        self.assertEqual(entries[0]["action"], "pair")
        self.assertEqual(entries[0]["result"], "ok")
        self.assertNotIn(code, json.dumps(entries))

    def test_a_bare_start_from_an_unlinked_chat_explains_pairing(self):
        self.bot.handle(message("/start"))
        self.assertIn("not linked", self.api.texts())

    def test_a_bare_start_from_a_linked_chat_shows_the_commands(self):
        self.link()
        self.bot.handle(message("/start"))
        self.assertIn("/incidents", self.api.texts())

    def test_the_username_becomes_the_link_label(self):
        code, _ = self.store.issue()
        self.bot.handle(message(f"/start {code}", username="alice"))
        self.assertEqual(self.store.links()[0]["label"], "alice")


class CommandTests(BotTestCase):
    def setUp(self):
        super().setUp()
        self.link()
        self.seed()

    def test_status_reports_live_counts(self):
        self.bot.handle(message("/status"))
        text = self.api.texts()
        self.assertIn("Packets: 1,234", text)
        self.assertIn("Database: ONLINE", text)
        self.assertIn("Telegram: CONNECTED", text)

    def test_incidents_lists_stored_incidents(self):
        self.bot.handle(message("/incidents"))
        text = self.api.texts()
        self.assertIn(INCIDENT, text)
        self.assertIn(OTHER_INCIDENT, text)

    def test_critical_lists_only_incidents_with_a_critical_finding(self):
        self.bot.handle(message("/critical"))
        text = self.api.texts()
        self.assertIn(INCIDENT, text)
        self.assertNotIn(OTHER_INCIDENT, text)

    def test_hosts_lists_observed_hosts(self):
        self.bot.handle(message("/hosts"))
        self.assertIn("192.0.2.10", self.api.texts())

    def test_incident_returns_the_evidence_timeline(self):
        self.bot.handle(message(f"/incident {INCIDENT}"))
        text = self.api.texts()
        self.assertIn("Evidence timeline:", text)
        self.assertIn("PORT_SCAN", text)
        self.assertIn("NETWORK_FANOUT", text)

    def test_incident_needs_a_well_formed_id(self):
        self.bot.handle(message("/incident ../../etc/passwd"))
        self.assertIn("Usage:", self.api.texts())

    def test_an_unknown_incident_is_reported_as_unknown(self):
        self.bot.handle(message("/incident NEMOS-000000000000"))
        self.assertIn("No incident", self.api.texts())

    def test_brief_answers_on_demand(self):
        self.bot.handle(message("/brief"))
        self.assertIn("NEMOS SECURITY BRIEF", self.api.texts())

    def test_an_unknown_command_gets_the_help_text(self):
        self.bot.handle(message("/wat"))
        self.assertIn("/incidents", self.api.texts())

    def test_a_command_addressed_to_the_bot_in_a_group_still_works(self):
        self.bot.handle(message("/status@nemos_sentinel_bot"))
        self.assertIn("NEMOS STATUS", self.api.texts())

    def test_plain_chat_is_ignored(self):
        self.bot.handle(message("hello there"))
        self.assertEqual(self.api.sent(), [])

    def test_command_arguments_are_bounded(self):
        """A 5000-character argument must not become a 5000-character reply."""
        self.bot.handle(message("/incident " + "A" * 5000))
        text = self.api.texts()
        self.assertIn("No incident", text)
        self.assertLess(len(text), 200)


class InlineActionTests(BotTestCase):
    def setUp(self):
        super().setUp()
        self.link()
        self.seed()

    def acknowledged(self) -> int:
        c = connect(self.db)
        try:
            return int(c.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 1"
            ).fetchone()["n"])
        finally:
            c.close()

    def test_acknowledging_one_alert_marks_it(self):
        self.bot.handle(callback("ack:1"))
        self.assertEqual(self.acknowledged(), 1)

    def test_acknowledging_an_incident_marks_all_of_its_findings(self):
        self.bot.handle(callback(f"acki:{INCIDENT}"))
        self.assertEqual(self.acknowledged(), 2)

    def test_investigate_sends_the_incident_detail(self):
        self.bot.handle(callback(f"inv:{INCIDENT}"))
        self.assertIn("Evidence timeline:", self.api.texts())

    def test_an_unlinked_chat_cannot_act(self):
        self.bot.handle(callback("acki:" + INCIDENT, chat_id=STRANGER))
        self.assertEqual(self.acknowledged(), 0)
        self.assertEqual(self.store.audit()[0]["result"], "denied")

    def test_authorisation_is_rechecked_when_the_button_is_pressed(self):
        """A chat unlinked after the alert was sent must not still be able to act."""
        self.store.unlink(CHAT)
        self.bot.handle(callback(f"acki:{INCIDENT}"))
        self.assertEqual(self.acknowledged(), 0)

    def test_every_action_is_audited_with_its_actor_and_target(self):
        self.bot.handle(callback(f"acki:{INCIDENT}"))
        entry = self.store.audit()[0]
        self.assertEqual(entry["actor"], CHAT)
        self.assertEqual(entry["action"], "acknowledge")
        self.assertEqual(entry["target"], INCIDENT)
        self.assertEqual(entry["result"], "ok")

    def test_a_malformed_target_changes_nothing(self):
        for data in ("acki:'; DROP TABLE alerts; --", "ack:notanumber",
                     "inv:../../etc", "unknown:x", "", ":"):
            with self.subTest(data=data):
                self.bot.handle(callback(data))
        self.assertEqual(self.acknowledged(), 0)
        c = connect(self.db)
        try:
            self.assertEqual(
                int(c.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]), 3)
        finally:
            c.close()

    def test_a_callback_is_always_answered_so_the_client_stops_spinning(self):
        self.bot.handle(callback(f"acki:{INCIDENT}"))
        methods = [m for m, _ in self.api.calls]
        self.assertIn("answerCallbackQuery", methods)


class ContainmentTests(BotTestCase):
    def test_containment_is_refused_when_no_hook_is_configured(self):
        self.link()
        self.bot.handle(callback(f"con:{INCIDENT}"))
        entry = self.store.audit()[0]
        self.assertEqual(entry["action"], "contain")
        self.assertEqual(entry["result"], "unavailable")
        self.assertIn("not configured", self.api.calls[-1][1]["text"])

    def test_a_configured_hook_runs_with_the_incident_id_as_its_only_argument(self):
        self.link()
        marker = Path(self.dir.name) / "contained.txt"
        hook = Path(self.dir.name) / "contain.sh"
        hook.write_text(f'#!/bin/sh\nprintf "%s" "$1" > {marker}\n')
        hook.chmod(0o755)
        self.bot.contain_hook = str(hook)
        self.bot.handle(callback(f"con:{INCIDENT}"))
        self.assertEqual(marker.read_text(), INCIDENT)
        self.assertEqual(self.store.audit()[0]["result"], "ok")

    def test_a_hostile_incident_id_never_reaches_the_hook(self):
        self.link()
        marker = Path(self.dir.name) / "ran.txt"
        hook = Path(self.dir.name) / "contain.sh"
        hook.write_text(f'#!/bin/sh\ntouch {marker}\n')
        hook.chmod(0o755)
        self.bot.contain_hook = str(hook)
        for hostile in ("; touch /tmp/pwned", "$(id)", "`id`", "../../bin/sh",
                        "NEMOS-../../x", "HOST-192.0.2.1"):
            with self.subTest(target=hostile):
                self.bot.handle(callback(f"con:{hostile}"))
                self.assertFalse(marker.exists())
                self.assertEqual(self.store.audit()[0]["result"], "denied")

    def test_a_missing_hook_fails_safely(self):
        self.link()
        self.bot.contain_hook = str(Path(self.dir.name) / "does-not-exist")
        self.bot.handle(callback(f"con:{INCIDENT}"))
        self.assertEqual(self.store.audit()[0]["result"], "error")

    def test_a_failing_hook_is_recorded_as_failed(self):
        self.link()
        hook = Path(self.dir.name) / "contain.sh"
        hook.write_text("#!/bin/sh\nexit 3\n")
        hook.chmod(0o755)
        self.bot.contain_hook = str(hook)
        self.bot.handle(callback(f"con:{INCIDENT}"))
        self.assertEqual(self.store.audit()[0]["result"], "failed")


class ResilienceTests(BotTestCase):
    def test_a_rate_limited_chat_is_dropped_not_answered(self):
        self.link()
        self.seed()
        for i in range(COMMAND_RATE + 5):
            self.bot.handle(message("/status", update_id=i))
        self.assertLessEqual(len(self.api.sent()), COMMAND_RATE)

    def test_one_chats_flood_does_not_spend_anothers_budget(self):
        self.link(CHAT)
        self.link(STRANGER)
        self.seed()
        for i in range(COMMAND_RATE + 5):
            self.bot.handle(message("/status", update_id=i))
        before = len(self.api.sent())
        self.bot.handle(message("/status", chat_id=STRANGER, update_id=999))
        self.assertEqual(len(self.api.sent()), before + 1)

    def test_a_send_failure_is_counted_rather_than_raised(self):
        self.link()
        self.api.fail_with = RuntimeError("telegram is down")
        self.assertFalse(self.bot.send(CHAT, "hello"))
        self.assertGreaterEqual(self.bot.errors, 1)

    def test_the_token_never_appears_in_a_recorded_error(self):
        self.link()
        self.api.fail_with = RuntimeError(f"bad request for bot{TOKEN}")
        self.bot.send(CHAT, "hello")
        self.assertNotIn(TOKEN, self.bot.last_error)
        self.assertIn("***", self.bot.last_error)

    def test_a_malformed_update_is_ignored(self):
        for update in ({}, {"message": None}, {"message": {}},
                       {"message": {"chat": {}}},
                       {"message": {"chat": {"id": "not-an-id"}, "text": "/status"}},
                       {"callback_query": {"id": "x"}}):
            with self.subTest(update=update):
                self.bot.handle(update)
        self.assertEqual(self.api.sent(), [])

    def test_metrics_never_carry_the_token(self):
        self.assertNotIn(TOKEN, json.dumps(self.bot.metrics()))

    def test_metrics_report_the_linked_audience(self):
        self.link()
        self.assertEqual(self.bot.metrics()["linked_chats"], 1)

    def test_a_bot_without_a_token_is_inactive_and_does_not_start(self):
        bot = TelegramBot("", self.store, self.db, api=self.api)
        bot.start()
        self.assertFalse(bot.active)
        self.assertFalse(bot.metrics()["running"])

    def test_polling_advances_the_offset_past_handled_updates(self):
        self.api.updates = [message("/status", update_id=7)]
        self.bot._poll()
        self.assertEqual(self.bot._offset, 8)

    def test_repeated_poll_failures_back_off_instead_of_hammering(self):
        """An invalid token fails identically forever; retrying every five
        seconds fills the log and changes nothing."""
        waits: list[float] = []
        self.api.fail_with = RuntimeError("Unauthorized")
        original = self.bot._stop.wait

        def record(timeout=None):
            waits.append(float(timeout or 0))
            if len(waits) >= 6:
                self.bot._stop.set()
            return original(0)

        self.bot._stop.wait = record  # type: ignore[method-assign]
        self.bot._run()
        self.assertEqual(waits, sorted(waits), waits)
        self.assertGreater(waits[-1], waits[0])
        self.assertLessEqual(max(waits), 300.0)

    def test_only_the_two_update_kinds_are_requested(self):
        self.bot._poll()
        _, params = self.api.calls[0]
        self.assertEqual(json.loads(params["allowed_updates"]),
                         ["message", "callback_query"])


class CollectorTests(BotTestCase):
    def test_status_reports_unknown_rather_than_guessing(self):
        state = collect_status(self.db)
        self.assertEqual(state["capture"], "UNKNOWN")
        self.assertEqual(state["telegram"], "DISCONNECTED")

    def test_status_reflects_a_blocked_capture(self):
        class Capture:
            def status(self):
                return {"display_state": "BLOCKED", "interface": "eth0",
                        "packets_seen": 0}

        state = collect_status(self.db, capture=Capture())
        self.assertEqual(state["capture"], "BLOCKED")
        self.assertEqual(state["interface"], "eth0")

    def test_a_capture_that_raises_is_reported_as_an_error(self):
        class Broken:
            def status(self):
                raise RuntimeError("boom")

        self.assertEqual(collect_status(self.db, capture=Broken())["capture"], "ERROR")

    def test_ml_states_come_from_the_analysis_engine(self):
        cases = [
            ({"model": {"loaded": True}}, "AVAILABLE"),
            ({"model": {"loaded": False}, "bootstrap": {"state": "TRAINING"}}, "LEARNING"),
            ({"model": {"loaded": False, "error": "no model"}}, "ERROR"),
            ({"model": {"loaded": False}}, "FALLBACK"),
        ]
        for info, expected in cases:
            with self.subTest(expected=expected):
                engine = type("A", (), {"status": lambda self, i=info: i})()
                self.assertEqual(collect_status(self.db, analysis=engine)["ml"], expected)

    def test_incidents_are_ordered_by_risk(self):
        self.seed()
        rows = collect_incidents(self.db)
        self.assertEqual(rows[0]["incident_id"], INCIDENT)
        self.assertGreaterEqual(rows[0]["risk_score"], rows[-1]["risk_score"])

    def test_critical_filters_to_incidents_carrying_a_critical_finding(self):
        self.seed()
        self.assertEqual([r["incident_id"] for r in collect_critical(self.db)],
                         [INCIDENT])

    def test_collectors_return_empty_on_an_empty_database(self):
        self.assertEqual(collect_incidents(self.db), [])
        self.assertEqual(collect_critical(self.db), [])
        self.assertEqual(collect_hosts(self.db), [])
        self.assertEqual(collect_incident(self.db, INCIDENT), (None, []))

    def test_an_invalid_incident_id_is_refused_before_any_query(self):
        self.seed()
        self.assertEqual(collect_incident(self.db, "'; DROP TABLE alerts; --"),
                         (None, []))

    def test_the_brief_only_reports_what_it_measured(self):
        self.seed()
        data = collect_brief(self.db)
        self.assertEqual(data["packets"], 1234)
        self.assertEqual(data["highest_risk"], 92)
        self.assertIn("PORT_SCAN", [d["threat"] for d in data["top_detections"]])

    def test_host_risk_matches_the_api_formula(self):
        self.seed()
        host = collect_hosts(self.db)[0]
        # max_risk 92 + min(20, 2*4) + min(10, 1*5), capped at 100.
        self.assertEqual(host["risk_score"], min(100, 92 + 8 + 5))


class BriefScheduleTests(BotTestCase):
    def test_it_fires_once_in_the_configured_hour(self):
        self.link()
        self.seed()
        brief = DailyBrief(self.bot, hour=7)
        at_seven = dt.datetime(2026, 9, 3, 7, 0, tzinfo=dt.timezone.utc)
        self.assertTrue(brief.run_once(at_seven))
        self.assertFalse(brief.run_once(at_seven.replace(minute=30)))
        self.assertEqual(brief.sent, 1)

    def test_it_fires_again_the_next_day(self):
        self.link()
        self.seed()
        brief = DailyBrief(self.bot, hour=7)
        brief.run_once(dt.datetime(2026, 9, 3, 7, 0, tzinfo=dt.timezone.utc))
        brief.run_once(dt.datetime(2026, 9, 4, 7, 0, tzinfo=dt.timezone.utc))
        self.assertEqual(brief.sent, 2)

    def test_a_missed_hour_does_not_produce_a_burst_of_catch_up_briefs(self):
        self.link()
        self.seed()
        brief = DailyBrief(self.bot, hour=7)
        for hour in range(24):
            brief.run_once(dt.datetime(2026, 9, 3, hour, tzinfo=dt.timezone.utc))
        self.assertEqual(brief.sent, 1)

    def test_nothing_is_sent_when_no_chat_is_paired(self):
        self.seed()
        brief = DailyBrief(self.bot, hour=7)
        self.assertFalse(brief.run_once(
            dt.datetime(2026, 9, 3, 7, tzinfo=dt.timezone.utc)))
        self.assertEqual(self.api.sent(), [])

    def test_the_hour_is_clamped_into_range(self):
        self.assertEqual(DailyBrief(self.bot, hour=99).hour, 23)
        self.assertEqual(DailyBrief(self.bot, hour=-5).hour, 0)

    def test_it_reaches_every_paired_chat(self):
        self.link(CHAT)
        self.link(STRANGER)
        self.seed()
        DailyBrief(self.bot, hour=7).run_once(
            dt.datetime(2026, 9, 3, 7, tzinfo=dt.timezone.utc))
        self.assertEqual({p["chat_id"] for p in self.api.sent()}, {CHAT, STRANGER})


if __name__ == "__main__":
    unittest.main()
