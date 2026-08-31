"""Capture-path tests, including real packet capture on loopback.

The live tests bind an actual capture socket on this machine's loopback
interface and generate their own traffic to it. Nothing leaves the host and no
third-party system is contacted. They skip when the environment cannot capture
(no CAP_NET_RAW, no Scapy, no loopback), so they are safe in CI.

Two bugs these cover, both found by running capture rather than reading it:

1. State only became "running" when the first packet arrived, so a correctly
   bound sensor on a quiet link reported "starting" forever -- indistinguishable
   from a capture that never came up.
2. If the capture thread died from a BaseException (a native panic, for
   instance) the status still reported "starting" with no error: a silent
   failure that looks like a sensor still coming up.
"""

import socket
import threading
import time
import unittest

from nemos.capture import PacketCapture
from nemos.detector import DetectionConfig, ThreatDetector


def _can_capture() -> bool:
    try:
        from scapy.all import get_if_list
    except ImportError:
        return False
    if "lo" not in get_if_list():
        return False
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    except (AttributeError, PermissionError, OSError):
        return False
    s.close()
    return True


CAN_CAPTURE = _can_capture()
requires_capture = unittest.skipUnless(CAN_CAPTURE, "raw capture unavailable here")


class StatusReportingTests(unittest.TestCase):
    """These need no privileges: they exercise how state is reported."""

    def test_dead_thread_is_never_reported_as_starting(self):
        capture = PacketCapture("lo", lambda event, kind: None)

        class Corpse:
            @staticmethod
            def is_alive():
                return False

        capture.thread = Corpse()
        capture._state = "starting"
        status = capture.status()
        self.assertEqual(status["state"], "failed")
        self.assertFalse(status["running"])
        self.assertIn("CAP_NET_RAW", status["error"])

    def test_existing_error_is_preserved_over_the_generic_message(self):
        capture = PacketCapture("lo", lambda event, kind: None)

        class Corpse:
            @staticmethod
            def is_alive():
                return False

        capture.thread = Corpse()
        capture._state = "running"
        capture._error = "Interface 'eth9' not found !"
        self.assertEqual(capture.status()["error"], "Interface 'eth9' not found !")

    def test_stopped_capture_is_not_reported_as_failed(self):
        capture = PacketCapture("lo", lambda event, kind: None)
        self.assertEqual(capture.status()["state"], "stopped")
        self.assertIsNone(capture.status()["error"])


@requires_capture
class LiveLoopbackCaptureTests(unittest.TestCase):
    """Real packets, real socket, this host's loopback only."""

    def setUp(self):
        self.events = []
        self.lock = threading.Lock()
        self.capture = PacketCapture("lo", self._record)
        self.capture.start()
        deadline = time.time() + 10
        while time.time() < deadline and self.capture.status()["state"] != "running":
            time.sleep(0.1)

    def tearDown(self):
        self.capture.stop(timeout=5)

    def _record(self, event, kind):
        with self.lock:
            self.events.append((event, kind))

    def test_state_is_running_before_any_packet_arrives(self):
        """The bug: this stayed "starting" until traffic happened to appear."""
        status = self.capture.status()
        self.assertEqual(status["state"], "running")
        self.assertTrue(status["running"])
        self.assertIsNone(status["error"])

    def test_real_tcp_traffic_is_captured_and_parsed(self):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(16)
        port = server.getsockname()[1]
        stop = threading.Event()

        def accept():
            server.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                    conn.sendall(b"nemos")
                    conn.close()
                except OSError:
                    pass

        threading.Thread(target=accept, daemon=True).start()
        try:
            for _ in range(12):
                client = socket.create_connection(("127.0.0.1", port), timeout=2)
                client.sendall(b"hello" * 8)
                client.recv(64)
                client.close()
            time.sleep(2.0)
        finally:
            stop.set()
            server.close()

        with self.lock:
            captured = list(self.events)
        self.assertTrue(captured, "no packets captured on loopback")

        tcp = [e for e, _ in captured if e.protocol == "TCP"]
        self.assertTrue(tcp, "loopback TCP was not parsed as TCP")
        sample = tcp[0]
        self.assertEqual(sample.source, "127.0.0.1")
        self.assertEqual(sample.destination, "127.0.0.1")
        self.assertGreater(sample.packet_size, 0)
        self.assertIsNotNone(sample.source_port)
        self.assertIsNotNone(sample.destination_port)
        self.assertEqual(sample.interface, "lo")
        self.assertTrue(sample.timestamp)
        self.assertGreater(self.capture.status()["packets_seen"], 0)
        self.assertIsNotNone(self.capture.status()["last_packet"])

    def test_captured_traffic_drives_the_detector(self):
        """End to end: real packets in, a real finding out."""
        detector = ThreatDetector(DetectionConfig())
        alerts = []
        for port in range(9200, 9240):
            probe = socket.socket()
            probe.settimeout(0.03)
            try:
                probe.connect_ex(("127.0.0.1", port))
            finally:
                probe.close()
        time.sleep(2.0)
        with self.lock:
            captured = list(self.events)
        for event, kind in captured:
            alerts.extend(detector.process(event, kind))
        self.assertTrue(alerts, "a 40-port loopback sweep produced no finding")
        self.assertIn("PORT_SCAN", {alert.threat for alert in alerts})


if __name__ == "__main__":
    unittest.main()
