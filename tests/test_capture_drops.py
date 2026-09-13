"""Tests for kernel-side packet drop accounting.

The claim this defends is the project's central one: ONLINE means NEMOS is
seeing the network. A capture socket whose ring buffer overflows keeps
delivering packets -- just not all of them -- so packet counts keep rising and
every other signal stays green while an arbitrary share of traffic goes
unexamined. Measured on a real socket during development: 48,000 packets
handed to an undrained socket, 47,980 of them dropped. Reporting that as
ONLINE, "all clear", is worse than failing to start, because nothing invites
investigation.

Two properties matter most:

- a drop rate over the alarm must take ONLINE away, and
- "cannot measure" must never be rendered as "zero drops", which is the same
  false reassurance in a different costume.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nemos.capture import (  # noqa: E402
    DEFAULT_DROP_ALARM,
    DROP_WINDOW_POLLS,
    STATE_DEGRADED,
    STATE_ONLINE,
    PacketCapture,
    drop_stats_supported,
    read_drop_stats,
    remedy,
)

LINUX = sys.platform.startswith("linux")


def sensor(**kw) -> PacketCapture:
    cap = PacketCapture("lo", lambda e, t: None, **kw)
    # Feed one getsockopt delta, as _poll_drops would from a live socket.
    def _poll(received: int, dropped: int) -> None:
        with cap._lock:
            cap._drop_visibility = True
            cap._kernel_received += received
            cap._kernel_dropped += dropped
            cap._drop_window.append((received, dropped))
    cap._poll = _poll
    return cap


class ReaderTests(unittest.TestCase):
    def test_a_non_socket_is_unknown_not_zero(self):
        self.assertIsNone(read_drop_stats(None))

    def test_a_socket_that_cannot_report_is_unknown_not_zero(self):
        """A TCP socket has no PACKET_STATISTICS. Zero would be a lie."""
        with socket.socket() as s:
            self.assertIsNone(read_drop_stats(s))

    @unittest.skipUnless(LINUX, "AF_PACKET is Linux-only")
    def test_support_matches_the_platform(self):
        self.assertTrue(drop_stats_supported())


class AccountingTests(unittest.TestCase):
    def test_unmeasurable_stays_unmeasurable_rather_than_becoming_zero(self):
        cap = sensor()
        cap._poll_drops(None)
        self.assertIs(cap._drop_visibility, False)
        self.assertIsNone(cap.drop_rate(),
                          "an unmeasurable rate must not read as 0% loss")

    def test_deltas_accumulate_because_the_kernel_resets_on_read(self):
        """getsockopt clears both counters, so each read is a delta."""
        cap = sensor()
        for _ in range(3):
            cap._poll(100, 10)
        self.assertEqual((cap._kernel_received, cap._kernel_dropped), (300, 30))
        self.assertAlmostEqual(cap.lifetime_drop_rate(), 30 / 330)

    def test_the_state_is_judged_on_recent_traffic_not_the_whole_run(self):
        """A burst of loss at startup must not pin the sensor to DEGRADED for
        the rest of its life -- an alarm that cannot clear is one operators
        learn to ignore. The first version of this accounting had exactly that
        bug: a freshly started sensor sat at 36% lifetime loss on an idle link.
        """
        cap = sensor()
        cap._poll(10, 990)                       # a bad first second
        self.assertGreater(cap.drop_rate(), cap.drop_alarm)
        for _ in range(DROP_WINDOW_POLLS):       # then a clean minute
            cap._poll(1000, 0)
        self.assertEqual(cap.drop_rate(), 0.0,
                         "the sensor must be able to recover")
        self.assertGreater(cap.lifetime_drop_rate(), 0.0,
                           "but the run's history is still reported")

    def test_recent_and_lifetime_are_reported_separately(self):
        cap = sensor()
        cap._poll(0, 1000)
        for _ in range(DROP_WINDOW_POLLS):
            cap._poll(1000, 0)
        body = cap.status()
        self.assertEqual(body["drop_rate"], 0.0)
        self.assertGreater(body["lifetime_drop_rate"], 0.0)
        self.assertEqual(body["kernel_dropped"], 1000)

    def test_no_traffic_yet_is_a_clean_rate_not_a_division_by_zero(self):
        cap = sensor()
        cap._drop_visibility = True
        self.assertEqual(cap.drop_rate(), 0.0)


class StateTests(unittest.TestCase):
    """ONLINE has to be earned twice: a packet arrived, and none were lost."""

    def online(self, cap, rate):
        return cap.display_state("running", True, 10, 0.0, now=99.0,
                                 drop_rate=rate)

    def test_losing_traffic_takes_online_away(self):
        cap = sensor()
        self.assertEqual(self.online(cap, 0.5), STATE_DEGRADED)

    def test_a_clean_socket_is_online(self):
        self.assertEqual(self.online(sensor(), 0.0), STATE_ONLINE)

    def test_the_alarm_is_a_floor_not_a_hair_trigger(self):
        """A single drop in a startup microburst is normal; an alarm nobody
        can clear is one everybody learns to ignore."""
        cap = sensor()
        self.assertEqual(self.online(cap, DEFAULT_DROP_ALARM / 2), STATE_ONLINE)
        self.assertEqual(self.online(cap, DEFAULT_DROP_ALARM), STATE_DEGRADED)

    def test_an_unmeasurable_rate_does_not_alarm_every_non_linux_host(self):
        self.assertEqual(self.online(sensor(), None), STATE_ONLINE)

    def test_the_alarm_is_configurable(self):
        self.assertEqual(self.online(sensor(drop_alarm=0.9), 0.5), STATE_ONLINE)

    def test_losing_traffic_does_not_mask_a_worse_problem(self):
        """BLOCKED and NO INTERFACE are still the answer; a drop rate cannot
        downgrade a sensor that is not running at all."""
        cap = sensor()
        self.assertEqual(
            cap.display_state("permission_denied", False, 0, None, drop_rate=0.9),
            "BLOCKED")

    def test_degraded_carries_an_actionable_sentence(self):
        text = remedy(STATE_DEGRADED)
        self.assertTrue(text)
        self.assertIn("buffer", text.lower())
        self.assertNotIn("root", text.lower(),
                         "running as root does not fix a slow reader")


class StatusTests(unittest.TestCase):
    def test_status_reports_the_counters_and_whether_they_are_real(self):
        cap = sensor()
        body = cap.status()
        for key in ("drop_visibility", "kernel_packets", "kernel_dropped",
                    "drop_rate"):
            self.assertIn(key, body)

    def test_an_unstarted_sensor_does_not_claim_zero_drops(self):
        self.assertIsNone(sensor().status()["drop_rate"])


@unittest.skipUnless(LINUX, "AF_PACKET is Linux-only")
class LiveOverflowTests(unittest.TestCase):
    """The end-to-end property, against a real kernel socket.

    Everything above can pass while the socket option is never actually read.
    This floods loopback hard enough that the kernel discards traffic, and
    checks the sensor notices.
    """

    def test_a_real_flood_is_seen_and_reported(self):
        cap = sensor()
        try:
            cap.start()

            # Decide before flooding, not after. A runner without CAP_NET_RAW
            # can never satisfy this test, and ten seconds of UDP to reach a
            # foregone skip is load nobody benefits from -- on CI that is every
            # job on every push. Visibility is only established by the first
            # poll, which lands one sniff() timeout after the socket opens, so
            # this waits for that rather than reading it immediately.
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                early = cap.status()
                if early["drop_visibility"]:
                    break
                if not early["running"] and early["error"]:
                    self.skipTest(f"capture did not start here: "
                                  f"{early['display_state']} -- {early['error']}")
                time.sleep(0.25)
            else:
                self.skipTest("no drop statistics appeared; this kernel or "
                              "socket does not expose PACKET_STATISTICS")

            stop = threading.Event()

            def blast():
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = b"x" * 64
                while not stop.is_set():
                    for port in range(20000, 20050):
                        try:
                            u.sendto(payload, ("127.0.0.1", port))
                        except OSError:
                            return

            threads = [threading.Thread(target=blast, daemon=True)
                       for _ in range(4)]
            for t in threads:
                t.start()
            time.sleep(10)
            stop.set()
            time.sleep(2.5)
            body = cap.status()
        finally:
            cap.stop()

        if not body["drop_visibility"]:
            self.skipTest("this kernel did not expose PACKET_STATISTICS")
        self.assertGreater(body["kernel_packets"], 0)
        if body["kernel_dropped"] == 0:
            self.skipTest("this machine drained the flood without dropping")
        self.assertGreater(body["drop_rate"], 0.0)
        self.assertEqual(body["display_state"], STATE_DEGRADED,
                         "a sensor losing traffic must not report ONLINE")
        self.assertIn("buffer", body["remedy"].lower())


if __name__ == "__main__":
    unittest.main()
