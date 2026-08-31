"""SensorWatchdog: alert on a dead capture thread, and tell systemd about it.

Confirmed on a real deployment: the capture thread can die while the rest of
the process (dashboard, API) keeps answering normally, so nothing else in
NEMOS notices. These tests exercise the watchdog the way it is actually
used -- through capture.status()'s dict shape and the notifier's submit()
signature -- not just its internals.
"""

from __future__ import annotations

import os
import socket
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone

from nemos.watchdog import SensorWatchdog, _parse_watchdog_usec, _seconds_since


def running(**overrides) -> dict:
    base = {"state": "running", "running": True, "interface": "eth0",
            "packets_seen": 1, "last_packet": None, "error": None}
    base.update(overrides)
    return base


class CaptureDeathIsAlerted(unittest.TestCase):
    def setUp(self):
        self.notified = []
        self.status = running()

    def notify(self, alert):
        self.notified.append(alert)
        return True

    def make(self, **kwargs):
        return SensorWatchdog(
            capture_status=lambda: self.status, notify=self.notify,
            heartbeat_seconds=0, **kwargs,
        )

    def test_healthy_capture_produces_no_alert(self):
        wd = self.make()
        wd._check()
        self.assertEqual(self.notified, [])

    def test_capture_failure_is_alerted_once(self):
        wd = self.make()
        self.status["state"] = "failed"
        self.status["error"] = "permission denied"
        wd._check()
        self.assertEqual(len(self.notified), 1)
        alert = self.notified[0]
        self.assertEqual(alert["threat"], "CAPTURE_THREAD_DOWN")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertIn("permission denied", alert["reason"])

    def test_repeated_failure_checks_do_not_duplicate_the_alert(self):
        wd = self.make()
        self.status["state"] = "failed"
        wd._check()
        wd._check()
        wd._check()
        self.assertEqual(len(self.notified), 1)

    def test_recovery_then_a_second_failure_alerts_again(self):
        wd = self.make()
        self.status["state"] = "failed"
        wd._check()
        self.status["state"] = "running"
        wd._check()
        self.status["state"] = "failed"
        wd._check()
        self.assertEqual(len(self.notified), 2)

    def test_every_unhealthy_capture_state_is_alerted(self):
        for state in ("failed", "error", "permission_denied", "unavailable"):
            with self.subTest(state=state):
                notified = []
                status = running(state=state)
                wd = SensorWatchdog(
                    capture_status=lambda s=status: s,
                    notify=lambda a, n=notified: n.append(a) or True,
                    heartbeat_seconds=0,
                )
                wd._check()
                self.assertEqual(len(notified), 1)

    def test_capture_disabled_is_never_treated_as_unhealthy(self):
        notified = []
        wd = SensorWatchdog(
            capture_status=None,
            notify=lambda a: notified.append(a) or True,
            heartbeat_seconds=0,
        )
        wd._check()
        self.assertEqual(notified, [])


class SilenceIsOptInAndDeduplicated(unittest.TestCase):
    def setUp(self):
        self.notified = []
        self.base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.now = self.base
        self.status = running(last_packet=self.base.isoformat(timespec="seconds"))

    def notify(self, alert):
        self.notified.append(alert)
        return True

    def make(self, heartbeat_seconds):
        return SensorWatchdog(
            capture_status=lambda: self.status, notify=self.notify,
            heartbeat_seconds=heartbeat_seconds, now=lambda: self.now,
        )

    def test_heartbeat_disabled_by_default_never_alerts_on_silence(self):
        wd = self.make(heartbeat_seconds=0)
        self.now = self.base + timedelta(hours=1)
        wd._check()
        self.assertEqual(self.notified, [])

    def test_silence_under_the_threshold_does_not_alert(self):
        wd = self.make(heartbeat_seconds=60)
        self.now = self.base + timedelta(seconds=30)
        wd._check()
        self.assertEqual(self.notified, [])

    def test_silence_over_the_threshold_alerts_once(self):
        wd = self.make(heartbeat_seconds=60)
        self.now = self.base + timedelta(seconds=90)
        wd._check()
        wd._check()
        self.assertEqual(len(self.notified), 1)
        self.assertEqual(self.notified[0]["threat"], "SENSOR_SILENT")

    def test_traffic_resuming_clears_the_flag_for_a_future_alert(self):
        wd = self.make(heartbeat_seconds=60)
        self.now = self.base + timedelta(seconds=90)
        wd._check()
        self.status["last_packet"] = (self.base + timedelta(seconds=95)).isoformat(timespec="seconds")
        self.now = self.base + timedelta(seconds=96)
        wd._check()
        self.now = self.base + timedelta(seconds=200)
        wd._check()
        self.assertEqual(len(self.notified), 2)

    def test_never_having_seen_a_packet_counts_from_watchdog_start(self):
        self.status["last_packet"] = None
        wd = self.make(heartbeat_seconds=10)
        wd._started_at = 0.0
        wd._clock = lambda: 20.0
        wd._check()
        self.assertEqual(len(self.notified), 1)


class SdNotifyIntegration(unittest.TestCase):
    def test_ready_and_watchdog_pings_reach_a_real_socket(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "notify.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(path)
        server.settimeout(2)
        try:
            status = running()
            wd = SensorWatchdog(
                capture_status=lambda: status, notify=lambda a: True,
                heartbeat_seconds=0, poll_seconds=0.05,
                environ={"NOTIFY_SOCKET": path},
            )
            wd.start()
            try:
                ready, _ = server.recvfrom(64)
                self.assertEqual(ready, b"READY=1")
                ping, _ = server.recvfrom(64)
                self.assertEqual(ping, b"WATCHDOG=1")
            finally:
                wd.stop()
        finally:
            server.close()

    def test_unhealthy_capture_stops_the_watchdog_ping(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "notify.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        server.bind(path)
        server.settimeout(1)
        try:
            status = running(state="failed")
            wd = SensorWatchdog(
                capture_status=lambda: status, notify=lambda a: True,
                heartbeat_seconds=0, poll_seconds=0.05,
                environ={"NOTIFY_SOCKET": path},
            )
            wd.start()
            try:
                server.recvfrom(64)  # READY=1
                with self.assertRaises(socket.timeout):
                    server.recvfrom(64)  # no WATCHDOG=1 while unhealthy
            finally:
                wd.stop()
        finally:
            server.close()

    def test_a_missing_notify_socket_is_a_silent_no_op(self):
        status = running()
        wd = SensorWatchdog(
            capture_status=lambda: status, notify=lambda a: True,
            heartbeat_seconds=0, environ={},
        )
        wd.start()
        time.sleep(0.02)
        wd.stop()  # must not raise

    def test_a_broken_socket_path_does_not_crash_the_check(self):
        status = running()
        wd = SensorWatchdog(
            capture_status=lambda: status, notify=lambda a: True,
            heartbeat_seconds=0, poll_seconds=0.05,
            environ={"NOTIFY_SOCKET": "/nonexistent/dir/notify.sock"},
        )
        wd.start()
        time.sleep(0.1)
        wd.stop()  # sendto failure is swallowed; the check itself must not die


class HelperFunctions(unittest.TestCase):
    def test_watchdog_usec_halves_the_poll_interval(self):
        wd = SensorWatchdog(
            capture_status=None, notify=lambda a: True,
            poll_seconds=30.0, environ={"WATCHDOG_USEC": "10000000"},  # 10s
        )
        self.assertEqual(wd._poll_seconds, 5.0)

    def test_watchdog_usec_never_widens_a_tighter_poll_interval(self):
        wd = SensorWatchdog(
            capture_status=None, notify=lambda a: True,
            poll_seconds=2.0, environ={"WATCHDOG_USEC": "10000000"},
        )
        self.assertEqual(wd._poll_seconds, 2.0)

    def test_parse_watchdog_usec_rejects_garbage(self):
        self.assertIsNone(_parse_watchdog_usec(None))
        self.assertIsNone(_parse_watchdog_usec(""))
        self.assertIsNone(_parse_watchdog_usec("not-a-number"))
        self.assertIsNone(_parse_watchdog_usec("0"))
        self.assertIsNone(_parse_watchdog_usec("-5"))

    def test_seconds_since_handles_missing_and_malformed_timestamps(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertIsNone(_seconds_since(None, now))
        self.assertIsNone(_seconds_since("not-a-timestamp", now))
        then = (now - timedelta(seconds=42)).isoformat(timespec="seconds")
        self.assertAlmostEqual(_seconds_since(then, now), 42, delta=1)


class ACheckThatRaisesDoesNotKillTheThread(unittest.TestCase):
    def test_the_poll_loop_survives_an_exception_in_check(self):
        calls = []

        def flaky_status():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return running()

        wd = SensorWatchdog(
            capture_status=flaky_status, notify=lambda a: True,
            heartbeat_seconds=0, poll_seconds=0.02,
        )
        wd.start()
        try:
            deadline = time.monotonic() + 2
            while len(calls) < 3 and time.monotonic() < deadline:
                time.sleep(0.02)
        finally:
            wd.stop()
        self.assertGreaterEqual(len(calls), 3, "watchdog thread stopped polling after an exception")


if __name__ == "__main__":
    unittest.main()
