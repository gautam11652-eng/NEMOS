from __future__ import annotations

import json
import os
import threading
import time
import unittest
from unittest.mock import patch

from nemos.notify import (
    AlertNotifier,
    DeliveryError,
    NotifierConfig,
    TelegramChannel,
    WebhookChannel,
    forget_bot_username,
    format_alert_text,
    resolve_bot_username,
    redact,
    valid_webhook_url,
)


def alert(severity="CRITICAL", source="192.0.2.10", threat="PORT_SCAN", **kw):
    base = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "threat": threat,
        "category": "NETWORK_RECONNAISSANCE",
        "source": source,
        "severity": severity,
        "risk_score": 91,
        "confidence": 88,
        "reason": "12 unique destination ports in 10s",
        "technique": "T1046",
        "incident_id": "NEMOS-ABC123",
    }
    base.update(kw)
    return base


class Recorder:
    """Test transport that records requests and returns a scripted status."""

    # A successful Telegram response always carries {"ok": true}; the previous
    # default of an empty body made this double more permissive than the real
    # API, which is why a 200-with-ok-false being counted as delivered went
    # unnoticed. Test doubles must not be kinder than the service they stand in
    # for.
    def __init__(self, status=200, body='{"ok":true,"result":{"message_id":1}}'):
        self.status = status
        self.body = body
        self.calls = []
        self.event = threading.Event()
        self._lock = threading.Lock()

    def __call__(self, method, url, headers, data, timeout):
        text = data.decode("utf-8")
        try:
            parsed = json.loads(text)
        except ValueError:
            # A text-format webhook body is not JSON by design.
            parsed = None
        with self._lock:
            self.calls.append({
                "method": method, "url": url, "headers": dict(headers),
                "body": parsed, "text": text, "timeout": timeout,
            })
        self.event.set()
        return self.status, self.body

    def wait(self, count=1, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if len(self.calls) >= count:
                    return True
            time.sleep(0.01)
        with self._lock:
            return len(self.calls) >= count


def notifier(recorder, **overrides):
    config = NotifierConfig(
        telegram_token="123:SECRET-BOT-TOKEN",
        telegram_chat_id="987654321",
        min_severity=overrides.pop("min_severity", "HIGH"),
        cooldown_seconds=overrides.pop("cooldown_seconds", 0.0),
        rate_per_minute=overrides.pop("rate_per_minute", 600),
        **overrides,
    )
    return AlertNotifier(config, transport=recorder)


class WebhookUrlTests(unittest.TestCase):
    def test_https_is_accepted(self):
        self.assertTrue(valid_webhook_url("https://soc.example.net/hook"))

    def test_plain_http_to_remote_host_is_rejected(self):
        # Alert bodies describe the monitored network; cleartext egress leaks it.
        self.assertFalse(valid_webhook_url("http://soc.example.net/hook"))

    def test_plain_http_to_loopback_is_allowed(self):
        self.assertTrue(valid_webhook_url("http://127.0.0.1:9000/hook"))
        self.assertTrue(valid_webhook_url("http://localhost:9000/hook"))

    def test_non_http_schemes_are_rejected(self):
        for url in ("file:///etc/passwd", "ftp://example.net/x", "javascript:alert(1)", ""):
            self.assertFalse(valid_webhook_url(url), url)

    def test_invalid_webhook_url_is_dropped_from_env_config(self):
        old = os.environ.get("NEMOS_WEBHOOK_URL")
        try:
            os.environ["NEMOS_WEBHOOK_URL"] = "http://evil.example.net/collect"
            self.assertEqual(NotifierConfig.from_env().webhook_url, "")
        finally:
            if old is None:
                os.environ.pop("NEMOS_WEBHOOK_URL", None)
            else:
                os.environ["NEMOS_WEBHOOK_URL"] = old


class RedactionTests(unittest.TestCase):
    def test_redact_removes_secret(self):
        self.assertEqual(redact("failed for 123:ABC", "123:ABC"), "failed for ***")

    def test_redact_ignores_empty_and_tiny_secrets(self):
        self.assertEqual(redact("unchanged", ""), "unchanged")
        self.assertEqual(redact("abc", "ab"), "abc")

    def test_telegram_error_does_not_leak_token(self):
        token = "123:SUPER-SECRET"
        channel = TelegramChannel(token, "42")

        def failing(method, url, headers, data, timeout):
            return 401, f"Unauthorized for bot{token}"

        with self.assertRaises(Exception) as ctx:
            channel.send(alert(), failing, 1.0)
        self.assertNotIn(token, str(ctx.exception))
        self.assertIn("***", str(ctx.exception))

    def test_metrics_never_contain_the_token(self):
        recorder = Recorder(status=401, body="Unauthorized")
        n = notifier(recorder)
        n.start()
        try:
            n.submit(alert())
            recorder.wait(1)
            time.sleep(0.05)
            blob = json.dumps(n.metrics())
            self.assertNotIn("SECRET-BOT-TOKEN", blob)
        finally:
            n.shutdown(timeout=2)


class MessageFormatTests(unittest.TestCase):
    def test_contains_key_fields(self):
        text = format_alert_text(alert())
        self.assertIn("CRITICAL", text)
        self.assertIn("PORT_SCAN", text)
        self.assertIn("192.0.2.10", text)
        self.assertIn("T1046", text)
        self.assertIn("NEMOS-ABC123", text)

    def test_message_is_truncated(self):
        text = format_alert_text(alert(reason="x" * 9000))
        self.assertLessEqual(len(text), 3500)

    def test_no_parse_mode_is_requested(self):
        # Alert text is untrusted-ish network data; it must not be parsed as markup.
        recorder = Recorder()
        TelegramChannel("t", "c").send(alert(), recorder, 1.0)
        self.assertNotIn("parse_mode", recorder.calls[0]["body"])

    def test_missing_optional_fields_are_omitted(self):
        text = format_alert_text({"threat": "X", "source": "1.2.3.4", "severity": "HIGH"})
        self.assertNotIn("ATT&CK", text)
        self.assertNotIn("incident", text)


class PairedAudienceTests(unittest.TestCase):
    """Delivery to chats that paired themselves, not only to TELEGRAM_CHAT_ID."""

    def test_a_paired_chat_receives_the_alert(self):
        recorder = Recorder()
        channel = TelegramChannel("t", "", chat_ids=lambda: ["111", "222"])
        channel.send(alert(), recorder, 1.0)
        chats = [call["body"]["chat_id"] for call in recorder.calls]
        self.assertEqual(chats, ["111", "222"])

    def test_the_configured_chat_id_and_paired_chats_are_merged(self):
        recorder = Recorder()
        channel = TelegramChannel("t", "999", chat_ids=lambda: ["111"])
        channel.send(alert(), recorder, 1.0)
        chats = [call["body"]["chat_id"] for call in recorder.calls]
        self.assertEqual(chats, ["999", "111"])

    def test_a_chat_listed_twice_is_sent_to_once(self):
        recorder = Recorder()
        channel = TelegramChannel("t", "999", chat_ids=lambda: ["999", "999"])
        channel.send(alert(), recorder, 1.0)
        self.assertEqual(len(recorder.calls), 1)

    def test_the_audience_is_read_fresh_on_every_send(self):
        """A chat paired a minute ago must not need a restart to be alerted."""
        chats: list[str] = []
        recorder = Recorder()
        channel = TelegramChannel("t", "", chat_ids=lambda: list(chats))
        chats.append("111")
        channel.send(alert(), recorder, 1.0)
        chats.append("222")
        channel.send(alert(), recorder, 1.0)
        self.assertEqual(len(recorder.calls), 3)

    def test_no_audience_is_a_delivery_failure_not_a_silent_success(self):
        channel = TelegramChannel("t", "", chat_ids=lambda: [])
        with self.assertRaises(DeliveryError):
            channel.send(alert(), Recorder(), 1.0)

    def test_a_failing_pairing_store_does_not_silence_the_configured_chat(self):
        def broken():
            raise RuntimeError("database is gone")

        recorder = Recorder()
        TelegramChannel("t", "999", chat_ids=broken).send(alert(), recorder, 1.0)
        self.assertEqual(len(recorder.calls), 1)

    def test_one_failing_chat_does_not_cancel_the_others(self):
        class PartialFailure(Recorder):
            def __call__(self, method, url, headers, data, timeout):
                payload = json.loads(data.decode("utf-8"))
                self.calls.append({"body": payload})
                if payload["chat_id"] == "111":
                    return 403, '{"ok": false, "description": "blocked"}'
                return 200, '{"ok": true}'

        recorder = PartialFailure()
        channel = TelegramChannel("t", "", chat_ids=lambda: ["111", "222"])
        channel.send(alert(), recorder, 1.0)  # must not raise
        self.assertEqual(len(recorder.calls), 2)

    def test_a_delivery_that_reached_nobody_raises(self):
        class AllFail(Recorder):
            def __call__(self, method, url, headers, data, timeout):
                self.calls.append({"body": json.loads(data.decode("utf-8"))})
                return 500, "server error"

        channel = TelegramChannel("t", "", chat_ids=lambda: ["111", "222"])
        with self.assertRaises(DeliveryError):
            channel.send(alert(), AllFail(), 1.0)

    def test_inline_buttons_ride_along_with_the_message(self):
        recorder = Recorder()
        TelegramChannel("t", "999").send(alert(), recorder, 1.0)
        payload = recorder.calls[0]["body"]
        labels = [b["text"] for row in payload["reply_markup"]["inline_keyboard"]
                  for b in row]
        self.assertIn("Acknowledge", labels)

    def test_a_notifier_with_a_token_and_a_pairing_source_builds_the_channel(self):
        """Requiring TELEGRAM_CHAT_ID here left a freshly paired sensor mute."""
        config = NotifierConfig(telegram_token="t")
        notifier = AlertNotifier(config, chat_ids=lambda: ["111"])
        self.assertEqual([c.name for c in notifier.channels], ["telegram"])

    def test_a_notifier_with_no_token_builds_no_telegram_channel(self):
        notifier = AlertNotifier(NotifierConfig(), chat_ids=lambda: ["111"])
        self.assertEqual(notifier.channels, [])


class WebhookTextFormatTests(unittest.TestCase):
    """The one delivery path that reaches a phone with no credential at all."""

    def channel(self, **kw):
        return WebhookChannel("https://ntfy.example/nemos-topic", **kw)

    def test_the_default_body_is_still_json(self):
        recorder = Recorder()
        self.channel().send(alert(), recorder, 1.0)
        call = recorder.calls[0]
        self.assertEqual(call["headers"]["Content-Type"], "application/json")
        self.assertEqual(call["body"]["source"], "NEMOS")

    def test_text_format_posts_the_rendered_report(self):
        recorder = Recorder()
        self.channel(body_format="text").send(alert(), recorder, 1.0)
        call = recorder.calls[0]
        self.assertTrue(call["headers"]["Content-Type"].startswith("text/plain"))
        self.assertIn("NEMOS SECURITY INCIDENT", call["text"])
        self.assertIn("192.0.2.10", call["text"])

    def test_no_credential_is_required_or_sent(self):
        recorder = Recorder()
        self.channel(body_format="text").send(alert(), recorder, 1.0)
        self.assertNotIn("Authorization", recorder.calls[0]["headers"])

    def test_push_headers_carry_severity(self):
        recorder = Recorder()
        self.channel(body_format="text").send(alert(severity="CRITICAL"), recorder, 1.0)
        headers = recorder.calls[0]["headers"]
        self.assertEqual(headers["X-Priority"], "5")
        self.assertEqual(headers["X-Tags"], "rotating_light")
        self.assertIn("CRITICAL", headers["X-Title"])

    def test_a_lower_severity_gets_a_lower_priority(self):
        recorder = Recorder()
        self.channel(body_format="text").send(alert(severity="LOW"), recorder, 1.0)
        self.assertEqual(recorder.calls[0]["headers"]["X-Priority"], "2")

    def test_a_newline_in_a_finding_cannot_inject_a_header(self):
        """Threat names come from observed traffic; the title is a boundary."""
        recorder = Recorder()
        self.channel(body_format="text").send(
            alert(threat="X\r\nX-Injected: yes"), recorder, 1.0)
        title = recorder.calls[0]["headers"]["X-Title"]
        self.assertNotIn("\n", title)
        self.assertNotIn("\r", title)
        self.assertNotIn("X-Injected", recorder.calls[0]["headers"])

    def test_a_non_latin1_finding_still_produces_a_sendable_header(self):
        recorder = Recorder()
        self.channel(body_format="text").send(alert(threat="scan \u2014 \u4f60\u597d"),
                                              recorder, 1.0)
        title = recorder.calls[0]["headers"]["X-Title"]
        title.encode("latin-1")  # must not raise; that would fail the request

    def test_the_format_comes_from_the_environment(self):
        with patch.dict(os.environ, {"NEMOS_WEBHOOK_FORMAT": "text"}):
            self.assertEqual(NotifierConfig.from_env().webhook_format, "text")
        with patch.dict(os.environ, {"NEMOS_WEBHOOK_FORMAT": "anything-else"}):
            self.assertEqual(NotifierConfig.from_env().webhook_format, "json")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NEMOS_WEBHOOK_FORMAT", None)
            self.assertEqual(NotifierConfig.from_env().webhook_format, "json")

    def test_the_notifier_builds_the_channel_with_the_configured_format(self):
        config = NotifierConfig(webhook_url="https://ntfy.example/t",
                                webhook_format="text")
        notifier = AlertNotifier(config)
        self.assertEqual(notifier.channels[0].body_format, "text")


class ResolveUsernameTests(unittest.TestCase):
    """TELEGRAM_BOT_USERNAME is derivable, so it is no longer required."""

    def setUp(self):
        forget_bot_username()
        self.addCleanup(forget_bot_username)

    def test_the_username_comes_back_from_getme(self):
        calls = []

        def api(token, method, params=None, timeout=15.0, api_base=""):
            calls.append(method)
            return {"username": "nemos_sentinel_bot", "first_name": "NEMOS"}

        username, error = resolve_bot_username("t" * 20, api=api)
        self.assertEqual(username, "nemos_sentinel_bot")
        self.assertEqual(error, "")
        self.assertEqual(calls, ["getMe"])

    def test_the_answer_is_cached_so_it_costs_one_call_per_process(self):
        calls = []

        def api(token, method, params=None, timeout=15.0, api_base=""):
            calls.append(method)
            return {"username": "cached_bot"}

        for _ in range(5):
            resolve_bot_username("t" * 20, api=api)
        self.assertEqual(len(calls), 1)

    def test_no_token_means_no_call_at_all(self):
        def api(*args, **kwargs):
            raise AssertionError("getMe must not be called without a token")

        username, error = resolve_bot_username("", api=api)
        self.assertEqual(username, "")
        self.assertIn("no bot token", error)

    def test_a_failure_is_reported_and_not_cached_as_success(self):
        attempts = []

        def failing(token, method, params=None, timeout=15.0, api_base=""):
            attempts.append(method)
            raise DeliveryError("could not reach Telegram")

        username, error = resolve_bot_username("t" * 20, api=failing, now=1000.0)
        self.assertEqual(username, "")
        self.assertIn("could not ask Telegram", error)
        # Briefly cached so an outage is not hammered...
        resolve_bot_username("t" * 20, api=failing, now=1001.0)
        self.assertEqual(len(attempts), 1)
        # ...but retried once the short failure window passes.
        resolve_bot_username("t" * 20, api=failing, now=1200.0)
        self.assertEqual(len(attempts), 2)

    def test_the_token_never_appears_in_an_error(self):
        token = "8640946561:AAsecret-part-of-the-token"  # noqa: S105

        def failing(t, method, params=None, timeout=15.0, api_base=""):
            raise DeliveryError(f"401 for bot{token}")

        _, error = resolve_bot_username(token, api=failing)
        self.assertNotIn(token, error)
        self.assertNotIn("AAsecret", error)
        self.assertIn("***", error)

    def test_a_username_telegram_returns_is_still_validated(self):
        """The value is interpolated into the link a QR code encodes."""
        def api(token, method, params=None, timeout=15.0, api_base=""):
            return {"username": "bad/../name"}

        username, error = resolve_bot_username("t" * 20, api=api)
        self.assertEqual(username, "")
        self.assertIn("no usable bot username", error)

    def test_different_tokens_do_not_share_a_cached_answer(self):
        def api(token, method, params=None, timeout=15.0, api_base=""):
            return {"username": f"bot_{token[-1]}"}

        self.assertEqual(resolve_bot_username("token_a", api=api)[0], "bot_a")
        self.assertEqual(resolve_bot_username("token_b", api=api)[0], "bot_b")


class BotUsernameTests(unittest.TestCase):
    def test_common_paste_forms_normalise_to_the_bare_username(self):
        for raw in ("nemos_bot", "@nemos_bot", "t.me/nemos_bot",
                    "https://t.me/nemos_bot", "https://t.me/nemos_bot?start=x"):
            with self.subTest(raw=raw):
                with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": raw}):
                    self.assertEqual(
                        NotifierConfig.from_env().telegram_bot_username, "nemos_bot")

    def test_anything_that_is_not_a_username_is_rejected(self):
        """This value is interpolated into the link a QR code encodes."""
        for raw in ("nemos bot", "nemos/../evil", "nemos?x=1&y=2", "n" * 40,
                    "<script>", "nemos-bot"):
            with self.subTest(raw=raw):
                with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": raw}):
                    self.assertEqual(
                        NotifierConfig.from_env().telegram_bot_username, "")


class DashboardUrlTests(unittest.TestCase):
    def test_an_http_or_https_base_is_accepted(self):
        for raw in ("https://nemos.example", "http://127.0.0.1:5000/"):
            with self.subTest(raw=raw):
                with patch.dict(os.environ, {"NEMOS_DASHBOARD_URL": raw}):
                    self.assertEqual(NotifierConfig.from_env().dashboard_url,
                                     raw.rstrip("/"))

    def test_anything_else_is_ignored(self):
        for raw in ("javascript:alert(1)", "file:///etc/passwd", "nemos.example",
                    "ftp://x.test"):
            with self.subTest(raw=raw):
                with patch.dict(os.environ, {"NEMOS_DASHBOARD_URL": raw}):
                    self.assertEqual(NotifierConfig.from_env().dashboard_url, "")


class DeliveryTests(unittest.TestCase):
    def test_alert_is_delivered_to_telegram(self):
        recorder = Recorder()
        n = notifier(recorder)
        n.start()
        try:
            self.assertTrue(n.submit(alert()))
            self.assertTrue(recorder.wait(1))
            call = recorder.calls[0]
            self.assertEqual(call["method"], "POST")
            self.assertIn("/sendMessage", call["url"])
            self.assertEqual(call["body"]["chat_id"], "987654321")
            self.assertIn("PORT_SCAN", call["body"]["text"])
        finally:
            n.shutdown(timeout=2)

    def test_webhook_receives_full_alert(self):
        recorder = Recorder()
        config = NotifierConfig(
            webhook_url="https://soc.example.net/hook", webhook_token="hook-secret",
            cooldown_seconds=0.0, rate_per_minute=600,
        )
        n = AlertNotifier(config, transport=recorder)
        n.start()
        try:
            n.submit(alert())
            self.assertTrue(recorder.wait(1))
            call = recorder.calls[0]
            self.assertEqual(call["headers"]["Authorization"], "Bearer hook-secret")
            self.assertEqual(call["body"]["alert"]["threat"], "PORT_SCAN")
        finally:
            n.shutdown(timeout=2)

    def test_delivery_counters_track_success(self):
        recorder = Recorder()
        n = notifier(recorder)
        n.start()
        try:
            n.submit(alert())
            recorder.wait(1)
            time.sleep(0.05)
            metrics = n.metrics()
            self.assertEqual(metrics["accepted"], 1)
            self.assertEqual(metrics["delivered"], 1)
            self.assertEqual(metrics["channels"]["telegram"]["sent"], 1)
        finally:
            n.shutdown(timeout=2)

    def test_failure_is_retried_once_then_counted(self):
        recorder = Recorder(status=500, body="boom")
        n = notifier(recorder)
        n.start()
        try:
            n.submit(alert())
            self.assertTrue(recorder.wait(2, timeout=6))
            time.sleep(0.1)
            metrics = n.metrics()
            self.assertEqual(metrics["failed"], 1)
            self.assertEqual(metrics["channels"]["telegram"]["failed"], 1)
            self.assertIn("500", metrics["channels"]["telegram"]["last_error"])
        finally:
            n.shutdown(timeout=3)


class SuppressionTests(unittest.TestCase):
    def test_low_severity_is_filtered(self):
        recorder = Recorder()
        n = notifier(recorder, min_severity="HIGH")
        n.start()
        try:
            self.assertFalse(n.submit(alert(severity="LOW")))
            self.assertFalse(n.submit(alert(severity="MEDIUM")))
            self.assertTrue(n.submit(alert(severity="HIGH")))
            self.assertEqual(n.metrics()["suppressed_severity"], 2)
        finally:
            n.shutdown(timeout=2)

    def test_repeat_finding_is_suppressed_by_cooldown(self):
        recorder = Recorder()
        n = notifier(recorder, cooldown_seconds=300.0)
        n.start()
        try:
            self.assertTrue(n.submit(alert()))
            self.assertFalse(n.submit(alert()))
            self.assertFalse(n.submit(alert()))
            # A different source is a different finding and still gets through.
            self.assertTrue(n.submit(alert(source="192.0.2.99")))
            self.assertEqual(n.metrics()["suppressed_cooldown"], 2)
        finally:
            n.shutdown(timeout=2)

    def test_rate_limit_bounds_a_flood(self):
        recorder = Recorder()
        n = notifier(recorder, rate_per_minute=3, cooldown_seconds=0.0)
        n.start()
        try:
            accepted = sum(n.submit(alert(source=f"192.0.2.{i}")) for i in range(25))
            self.assertEqual(accepted, 3)
            self.assertEqual(n.metrics()["suppressed_rate"], 22)
        finally:
            n.shutdown(timeout=2)

    def test_cooldown_map_is_bounded(self):
        from nemos.notify import MAX_COOLDOWN_ENTRIES

        recorder = Recorder()
        n = notifier(recorder, cooldown_seconds=3600.0, rate_per_minute=600)
        n.start()
        try:
            # Spoofed sources must not be able to grow detector-adjacent state.
            for i in range(MAX_COOLDOWN_ENTRIES + 200):
                n._allow(alert(source=f"10.0.{i // 256}.{i % 256}"), time.monotonic())
            self.assertLessEqual(len(n._cooldown), MAX_COOLDOWN_ENTRIES)
        finally:
            n.shutdown(timeout=2)


class LifecycleTests(unittest.TestCase):
    def test_inactive_without_channels(self):
        n = AlertNotifier(NotifierConfig())
        n.start()
        self.assertFalse(n.active)
        self.assertFalse(n.submit(alert()))
        n.shutdown(timeout=1)

    def test_disabled_by_configuration(self):
        recorder = Recorder()
        n = notifier(recorder, enabled=False)
        n.start()
        self.assertFalse(n.active)
        self.assertFalse(n.submit(alert()))
        n.shutdown(timeout=1)

    def test_submit_before_start_is_rejected(self):
        n = notifier(Recorder())
        self.assertFalse(n.submit(alert()))
        n.shutdown(timeout=1)

    def test_shutdown_is_idempotent(self):
        n = notifier(Recorder())
        n.start()
        n.shutdown(timeout=2)
        n.shutdown(timeout=2)

    def test_queue_full_is_counted_not_blocking(self):
        blocked = threading.Event()

        def slow(method, url, headers, data, timeout):
            blocked.wait(2.0)
            return 200, ""

        config = NotifierConfig(
            telegram_token="123:X", telegram_chat_id="1", cooldown_seconds=0.0,
            rate_per_minute=600, queue_size=8,
        )
        n = AlertNotifier(config, transport=slow)
        n.start()
        try:
            started = time.monotonic()
            for i in range(200):
                n.submit(alert(source=f"192.0.2.{i % 250}"))
            # The capture path must never be blocked by a stalled channel.
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertGreater(n.metrics()["dropped_queue_full"], 0)
        finally:
            blocked.set()
            n.shutdown(timeout=3)

    def test_worker_survives_a_channel_that_raises(self):
        def exploding(method, url, headers, data, timeout):
            raise RuntimeError("network down")

        config = NotifierConfig(
            telegram_token="123:X", telegram_chat_id="1",
            cooldown_seconds=0.0, rate_per_minute=600,
        )
        n = AlertNotifier(config, transport=exploding)
        n.start()
        try:
            n.submit(alert())
            time.sleep(1.5)
            self.assertEqual(n.metrics()["failed"], 1)
            # Thread is still alive and accepting work.
            self.assertTrue(n.submit(alert(source="192.0.2.50")))
        finally:
            n.shutdown(timeout=3)


class ConfigTests(unittest.TestCase):
    def test_defaults_are_conservative(self):
        config = NotifierConfig()
        self.assertEqual(config.min_severity, "HIGH")
        self.assertFalse(config.active)

    def test_invalid_severity_falls_back(self):
        old = os.environ.get("NEMOS_NOTIFY_MIN_SEVERITY")
        try:
            os.environ["NEMOS_NOTIFY_MIN_SEVERITY"] = "bogus"
            self.assertEqual(NotifierConfig.from_env().min_severity, "HIGH")
            os.environ["NEMOS_NOTIFY_MIN_SEVERITY"] = "critical"
            self.assertEqual(NotifierConfig.from_env().min_severity, "CRITICAL")
        finally:
            if old is None:
                os.environ.pop("NEMOS_NOTIFY_MIN_SEVERITY", None)
            else:
                os.environ["NEMOS_NOTIFY_MIN_SEVERITY"] = old

    def test_non_finite_values_fall_back_to_defaults(self):
        old = os.environ.get("NEMOS_NOTIFY_TIMEOUT")
        try:
            os.environ["NEMOS_NOTIFY_TIMEOUT"] = "nan"
            self.assertEqual(NotifierConfig.from_env().timeout_seconds, 5.0)
            os.environ["NEMOS_NOTIFY_TIMEOUT"] = "inf"
            self.assertEqual(NotifierConfig.from_env().timeout_seconds, 5.0)
        finally:
            if old is None:
                os.environ.pop("NEMOS_NOTIFY_TIMEOUT", None)
            else:
                os.environ["NEMOS_NOTIFY_TIMEOUT"] = old


if __name__ == "__main__":
    unittest.main()


class TelegramApiContractTests(unittest.TestCase):
    """The Bot API reports its outcome in the body, not only the status line.

    Telegram can answer HTTP 200 with ``{"ok": false}``. Treating the status
    code as proof of delivery counted those as sent, so the operator saw a
    success for a message that never arrived -- the worst failure mode an
    alerting path has, because it is silent.
    """

    TOKEN = "1234567890:AAFAKEfakeFAKEfakeFAKEfakeFAKEfake00"

    def _channel(self):
        from nemos.notify import TelegramChannel
        return TelegramChannel(self.TOKEN, "-1001234567890", api_base="https://example.invalid")

    def _transport(self, status, body):
        def transport(method, url, headers, data, timeout):
            self.captured = {"method": method, "url": url, "headers": headers,
                             "body": json.loads(data.decode())}
            return status, body
        return transport

    def test_ok_true_is_delivered(self):
        self._channel().send({"threat": "T"}, self._transport(200, '{"ok":true,"result":{}}'), 5)

    def test_two_hundred_with_ok_false_is_a_failure(self):
        from nemos.notify import DeliveryError
        body = '{"ok":false,"description":"Bad Request: message text is empty"}'
        with self.assertRaises(DeliveryError) as caught:
            self._channel().send({"threat": "T"}, self._transport(200, body), 5)
        self.assertIn("reported failure", str(caught.exception))
        self.assertIn("message text is empty", str(caught.exception))

    def test_two_hundred_with_unparseable_body_is_a_failure(self):
        """A captive portal or proxy answering 200 with HTML is not delivery."""
        from nemos.notify import DeliveryError
        with self.assertRaises(DeliveryError) as caught:
            self._channel().send({"threat": "T"}, self._transport(200, "<html>hi</html>"), 5)
        self.assertIn("unparseable", str(caught.exception))

    def test_error_statuses_never_disclose_the_token(self):
        from nemos.notify import DeliveryError
        for status, body in (
            (401, f'{{"ok":false,"description":"Unauthorized: bot{TelegramApiContractTests.TOKEN}"}}'),
            (400, '{"ok":false,"description":"Bad Request: chat not found"}'),
            (403, '{"ok":false,"description":"Forbidden: bot was blocked by the user"}'),
            (429, '{"ok":false,"description":"Too Many Requests: retry after 30"}'),
        ):
            with self.assertRaises(DeliveryError) as caught:
                self._channel().send({"threat": "T"}, self._transport(status, body), 5)
            self.assertNotIn(self.TOKEN, str(caught.exception), f"token leaked on {status}")

    def test_request_matches_the_bot_api_contract(self):
        self._channel().send(
            {"severity": "HIGH", "threat": "C2_BEACONING", "source": "10.0.0.5"},
            self._transport(200, '{"ok":true}'), 5)
        self.assertEqual(self.captured["method"], "POST")
        self.assertTrue(self.captured["url"].endswith("/sendMessage"))
        self.assertIn(f"/bot{self.TOKEN}/", self.captured["url"])
        self.assertEqual(self.captured["headers"]["Content-Type"], "application/json")
        self.assertEqual(self.captured["body"]["chat_id"], "-1001234567890")
        self.assertTrue(self.captured["body"]["disable_web_page_preview"])
        # No parse_mode: alert text describes observed traffic and must never be
        # handed to a markup parser.
        self.assertNotIn("parse_mode", self.captured["body"])
        self.assertIn("C2_BEACONING", self.captured["body"]["text"])


class TelegramVerifierTests(unittest.TestCase):
    """tools/verify_telegram.py is how an operator proves the last hop."""

    def _tool(self):
        import importlib.util
        from pathlib import Path
        path = Path(__file__).resolve().parents[1] / "tools" / "verify_telegram.py"
        spec = importlib.util.spec_from_file_location("verify_telegram", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_it_exists_and_imports(self):
        self.assertTrue(hasattr(self._tool(), "main"))

    def test_missing_credentials_exit_without_sending(self):
        import os
        from unittest import mock
        tool = self._tool()
        with mock.patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_CHAT_ID": ""}), \
             mock.patch("sys.argv", ["verify_telegram.py"]), \
             mock.patch.object(tool, "load_dotenv", lambda path: {}):
            self.assertEqual(tool.main(), 2)

    def test_every_documented_failure_has_a_diagnosis(self):
        tool = self._tool()
        for message, expect in (
            ("telegram responded 401: Unauthorized", "token"),
            ("chat not found", "TELEGRAM_CHAT_ID"),
            ("bot was blocked by the user", "blocked"),
            ("Too Many Requests", "Rate limited"),
        ):
            self.assertIn(expect, tool.diagnose(message))

    def test_unknown_errors_still_get_actionable_advice(self):
        self.assertTrue(self._tool().diagnose("something entirely new").strip())

    def test_the_test_message_is_labelled_as_a_test(self):
        alert = self._tool().build_alert("LOW")
        self.assertEqual(alert["threat"], "NEMOS_DELIVERY_TEST")
        self.assertIn("Not a detection", alert["reason"])
        self.assertEqual(alert["risk_score"], 0)
