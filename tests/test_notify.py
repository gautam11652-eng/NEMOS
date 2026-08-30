from __future__ import annotations

import json
import os
import threading
import time
import unittest

from nemos.notify import (
    AlertNotifier,
    NotifierConfig,
    TelegramChannel,
    format_alert_text,
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

    def __init__(self, status=200, body=""):
        self.status = status
        self.body = body
        self.calls = []
        self.event = threading.Event()
        self._lock = threading.Lock()

    def __call__(self, method, url, headers, data, timeout):
        with self._lock:
            self.calls.append({
                "method": method, "url": url, "headers": dict(headers),
                "body": json.loads(data.decode("utf-8")), "timeout": timeout,
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
