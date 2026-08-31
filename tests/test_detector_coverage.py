"""Tests for the detections added beyond scanning and flooding.

Each rule is tested twice: once that it fires on the traffic shape it exists to
catch, and once that it stays quiet on a shape that resembles it but is benign.
A detection that only has the positive test is a detection whose false-positive
behaviour nobody has checked.
"""

import unittest

from nemos.attack import TECHNIQUES
from nemos.detector import DetectionConfig, ThreatDetector
from nemos.models import TrafficEvent


def event(source: str, destination: str, port: int | None, protocol: str = "TCP",
          flags: str = "S", size: int = 60) -> TrafficEvent:
    return TrafficEvent(
        "2026-01-01T00:00:00Z", source, destination, protocol,
        source_port=40000, destination_port=port, packet_size=size, flags=flags,
    )


def threats(alerts) -> set[str]:
    return {a.threat for a in alerts}


class StealthScanTests(unittest.TestCase):
    """NULL, FIN and Xmas probes are defined by their TCP flag combination."""

    def _scan(self, flags: str) -> list:
        detector = ThreatDetector()
        found = []
        for port in range(100, 110):
            found += detector.process(event("10.0.0.5", "10.0.0.9", port, flags=flags))
        return found

    def test_null_scan_detected(self):
        self.assertIn("TCP_NULL_SCAN", threats(self._scan("")))

    def test_fin_scan_detected(self):
        self.assertIn("TCP_FIN_SCAN", threats(self._scan("F")))

    def test_xmas_scan_detected(self):
        self.assertIn("TCP_XMAS_SCAN", threats(self._scan("FPU")))

    def test_ordinary_syn_traffic_is_not_a_stealth_scan(self):
        found = self._scan("S")
        self.assertFalse({t for t in threats(found) if "NULL" in t or "XMAS" in t})

    def test_established_traffic_is_not_a_stealth_scan(self):
        # PSH+ACK is an ordinary data segment on an open connection.
        self.assertNotIn("TCP_FIN_SCAN", threats(self._scan("PA")))

    def test_evidence_names_the_scan_type(self):
        alert = next(a for a in self._scan("") if a.threat == "TCP_NULL_SCAN")
        self.assertEqual(alert.evidence["scan_type"], "tcp_null")
        self.assertTrue(alert.evidence["ports"])


class LateralMovementTests(unittest.TestCase):
    def test_internal_admin_sweep_detected(self):
        detector = ThreatDetector()
        found = []
        for host in range(10, 20):
            found += detector.process(event("10.0.0.5", f"10.0.0.{host}", 445))
        alerts = [a for a in found if a.threat == "LATERAL_MOVEMENT"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1021")

    def test_external_source_is_not_lateral_movement(self):
        # The same shape from a public address is inbound reconnaissance. It
        # may raise other findings, but calling it lateral movement would
        # misstate where the actor already is.
        detector = ThreatDetector()
        found = []
        for host in range(10, 20):
            found += detector.process(event("203.0.113.9", f"10.0.0.{host}", 445))
        self.assertNotIn("LATERAL_MOVEMENT", threats(found))

    def test_internal_traffic_on_ordinary_ports_is_not_lateral_movement(self):
        detector = ThreatDetector()
        found = []
        for host in range(10, 20):
            found += detector.process(event("10.0.0.5", f"10.0.0.{host}", 443))
        self.assertNotIn("LATERAL_MOVEMENT", threats(found))


class BruteForceTests(unittest.TestCase):
    def test_repeated_attempts_on_one_service_detected(self):
        detector = ThreatDetector()
        found = []
        for _ in range(25):
            found += detector.process(event("10.0.0.5", "10.0.0.9", 22))
        alerts = [a for a in found if a.threat == "CREDENTIAL_BRUTE_FORCE"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].evidence["service_port"], 22)
        self.assertEqual(alerts[0].evidence["target"], "10.0.0.9")

    def test_attempts_spread_across_hosts_do_not_trigger(self):
        # Password spraying is a different shape and would need its own rule;
        # this asserts the per-target counter is not accidentally global.
        detector = ThreatDetector()
        found = []
        for host in range(10, 35):
            found += detector.process(event("10.0.0.5", f"10.0.0.{host}", 22))
        self.assertNotIn("CREDENTIAL_BRUTE_FORCE", threats(found))

    def test_non_auth_service_does_not_trigger(self):
        detector = ThreatDetector()
        found = []
        for _ in range(30):
            found += detector.process(event("10.0.0.5", "10.0.0.9", 8080))
        self.assertNotIn("CREDENTIAL_BRUTE_FORCE", threats(found))

    def test_success_is_not_claimed(self):
        detector = ThreatDetector()
        found = []
        for _ in range(25):
            found += detector.process(event("10.0.0.5", "10.0.0.9", 22))
        alert = next(a for a in found if a.threat == "CREDENTIAL_BRUTE_FORCE")
        self.assertIn("success cannot be determined", alert.evidence["note"])


class ExfiltrationTests(unittest.TestCase):
    def test_large_external_transfer_detected(self):
        detector = ThreatDetector(DetectionConfig(exfil_bytes=1_000_000))
        found = []
        for _ in range(30):
            found += detector.process(
                event("10.0.0.5", "203.0.113.7", 443, flags="PA", size=60_000))
        alerts = [a for a in found if a.threat == "DATA_EXFILTRATION_VOLUME"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1048")

    def test_internal_transfer_is_not_exfiltration(self):
        # Data that never leaves the network is not exfiltration by this
        # definition, and a file server would otherwise alert constantly.
        detector = ThreatDetector(DetectionConfig(exfil_bytes=1_000_000))
        found = []
        for _ in range(30):
            found += detector.process(
                event("10.0.0.5", "10.0.0.9", 445, flags="PA", size=60_000))
        self.assertNotIn("DATA_EXFILTRATION_VOLUME", threats(found))

    def test_small_transfer_does_not_trigger(self):
        detector = ThreatDetector(DetectionConfig(exfil_bytes=1_000_000))
        found = []
        for _ in range(10):
            found += detector.process(
                event("10.0.0.5", "203.0.113.7", 443, flags="PA", size=500))
        self.assertNotIn("DATA_EXFILTRATION_VOLUME", threats(found))

    def test_finding_states_a_backup_looks_identical(self):
        detector = ThreatDetector(DetectionConfig(exfil_bytes=1_000_000))
        found = []
        for _ in range(30):
            found += detector.process(
                event("10.0.0.5", "203.0.113.7", 443, flags="PA", size=60_000))
        alert = next(a for a in found if a.threat == "DATA_EXFILTRATION_VOLUME")
        self.assertIn("backup", alert.evidence["note"])


class DnsTunnelingTests(unittest.TestCase):
    def test_large_sustained_dns_detected(self):
        detector = ThreatDetector()
        found = []
        for _ in range(40):
            found += detector.process(
                event("10.0.0.5", "10.0.0.53", 53, protocol="DNS", flags="", size=400))
        alerts = [a for a in found if a.threat == "DNS_TUNNELING_PATTERN"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1071.004")

    def test_ordinary_dns_does_not_trigger(self):
        # Normal queries are small. Volume alone is DNS_BURST's job.
        detector = ThreatDetector()
        found = []
        for _ in range(40):
            found += detector.process(
                event("10.0.0.5", "10.0.0.53", 53, protocol="DNS", flags="", size=80))
        self.assertNotIn("DNS_TUNNELING_PATTERN", threats(found))

    def test_evidence_admits_payloads_are_not_inspected(self):
        detector = ThreatDetector()
        found = []
        for _ in range(40):
            found += detector.process(
                event("10.0.0.5", "10.0.0.53", 53, protocol="DNS", flags="", size=400))
        alert = next(a for a in found if a.threat == "DNS_TUNNELING_PATTERN")
        self.assertIn("not inspected", alert.evidence["note"])


class SuspiciousPortTests(unittest.TestCase):
    def test_mining_pool_ports_detected(self):
        detector = ThreatDetector()
        found = []
        for _ in range(12):
            found += detector.process(event("10.0.0.5", "203.0.113.7", 3333))
        alerts = [a for a in found if a.threat == "CRYPTO_MINING_PATTERN"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1496")

    def test_tor_ports_detected(self):
        detector = ThreatDetector()
        found = []
        for _ in range(12):
            found += detector.process(event("10.0.0.5", "203.0.113.7", 9001))
        alerts = [a for a in found if a.threat == "TOR_CONNECTION_PATTERN"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1090.003")

    def test_heuristic_is_labelled_as_such(self):
        detector = ThreatDetector()
        found = []
        for _ in range(12):
            found += detector.process(event("10.0.0.5", "203.0.113.7", 3333))
        alert = next(a for a in found if a.threat == "CRYPTO_MINING_PATTERN")
        self.assertIn("heuristic", alert.evidence["note"])

    def test_ordinary_https_is_not_flagged(self):
        detector = ThreatDetector()
        found = []
        for _ in range(12):
            found += detector.process(event("10.0.0.5", "203.0.113.7", 443))
        self.assertFalse({"CRYPTO_MINING_PATTERN", "TOR_CONNECTION_PATTERN"} & threats(found))


class BeaconingTests(unittest.TestCase):
    """Periodicity is measured across a horizon longer than the window."""

    def _run(self, intervals, port=8443, destination="203.0.113.7"):
        detector = ThreatDetector()
        found = []
        clock = 1000.0
        for gap in intervals:
            clock += gap
            found += detector.process(
                event("10.0.0.5", destination, port, flags="PA"), now=clock)
        return found

    def test_regular_callbacks_detected(self):
        found = self._run([30.0] * 8)
        alerts = [a for a in found if a.threat == "C2_BEACONING"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1071")
        self.assertEqual(alerts[0].evidence["mean_interval_seconds"], 30.0)

    def test_small_jitter_still_detected(self):
        # Real implants jitter slightly; a rule that only caught perfect
        # timers would be trivial to evade.
        found = self._run([30.0, 31.0, 29.0, 30.5, 29.5, 30.0, 31.0, 29.0])
        self.assertIn("C2_BEACONING", threats(found))

    def test_irregular_traffic_is_not_a_beacon(self):
        found = self._run([5.0, 90.0, 12.0, 240.0, 3.0, 160.0, 45.0, 8.0])
        self.assertNotIn("C2_BEACONING", threats(found))

    def test_too_few_contacts_is_not_a_beacon(self):
        found = self._run([30.0] * 3)
        self.assertNotIn("C2_BEACONING", threats(found))

    def test_ntp_and_dns_are_excluded(self):
        # Both are periodic by design. Flagging them would drown real findings.
        for port in (53, 123):
            found = self._run([30.0] * 8, port=port)
            self.assertNotIn("C2_BEACONING", threats(found), f"port {port}")

    def test_rapid_packets_are_one_contact_not_a_beacon(self):
        # A single transfer sends packets at line rate. Counting each as a
        # contact would make every download a perfectly regular beacon.
        found = self._run([0.01] * 40)
        self.assertNotIn("C2_BEACONING", threats(found))

    def test_contact_table_is_bounded(self):
        detector = ThreatDetector(DetectionConfig(max_sources=4))
        clock = 1000.0
        for i in range(500):
            clock += 3.0
            detector.process(event("10.0.0.5", f"203.0.113.{i % 250}", 8443), now=clock)
        self.assertLessEqual(len(detector.contacts), detector.cfg.max_sources * 4)


class CatalogTests(unittest.TestCase):
    def test_every_emitted_technique_is_in_the_catalog(self):
        """A technique ID with no catalog entry renders as a bare string."""
        import re
        from pathlib import Path

        source = Path("nemos/detector.py").read_text()
        emitted = set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"', source))
        self.assertTrue(emitted)
        self.assertEqual(emitted - set(TECHNIQUES), set())


class NormalTrafficTests(unittest.TestCase):
    def test_benign_traffic_raises_no_new_detections(self):
        """The whole point: none of these rules fire on ordinary traffic.

        Uses the same synthetic 'normal' profile the demo and training corpus
        are built from, so this guards against a threshold that looks
        reasonable in isolation but alerts constantly in practice.
        """
        import sys
        from pathlib import Path
        tools = str(Path("tools").resolve())
        if tools not in sys.path:
            sys.path.insert(0, tools)
        from scenarios import build

        detector = ThreatDetector()
        found = []
        for offset, traffic in build("normal").events:
            found += detector.process(traffic, traffic.protocol, now=1000.0 + offset)

        new_rules = {
            "TCP_NULL_SCAN", "TCP_FIN_SCAN", "TCP_XMAS_SCAN", "LATERAL_MOVEMENT",
            "CREDENTIAL_BRUTE_FORCE", "DATA_EXFILTRATION_VOLUME",
            "DNS_TUNNELING_PATTERN", "CRYPTO_MINING_PATTERN",
            "TOR_CONNECTION_PATTERN", "C2_BEACONING",
        }
        self.assertEqual(threats(found) & new_rules, set())


if __name__ == "__main__":
    unittest.main()


class InternalNetworkTests(unittest.TestCase):
    """Regression tests for the address-classification bug.

    ``ipaddress.is_private`` and ``is_global`` both treat the RFC 5737
    documentation ranges as non-global. Using either made synthetic external
    hosts look internal, which disabled exfiltration detection in precisely the
    traffic used to demonstrate it.
    """

    def test_rfc1918_is_internal(self):
        detector = ThreatDetector()
        for address in ("10.0.0.5", "172.16.4.1", "192.168.1.7", "127.0.0.1"):
            self.assertTrue(detector._private(address), address)

    def test_documentation_ranges_are_external(self):
        detector = ThreatDetector()
        for address in ("192.0.2.5", "198.51.100.9", "203.0.113.7"):
            self.assertFalse(detector._private(address), address)

    def test_public_addresses_are_external(self):
        detector = ThreatDetector()
        self.assertFalse(detector._private("8.8.8.8"))

    def test_unparseable_address_is_external(self):
        # Counting it as internal would let a malformed value suppress an
        # exfiltration finding.
        detector = ThreatDetector()
        self.assertFalse(detector._private("not-an-address"))

    def test_internal_ranges_are_configurable(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"NEMOS_INTERNAL_NETWORKS": "203.0.113.0/24"}):
            detector = ThreatDetector()
        self.assertTrue(detector._private("203.0.113.7"))
        self.assertFalse(detector._private("10.0.0.5"))

    def test_malformed_override_falls_back_to_defaults(self):
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"NEMOS_INTERNAL_NETWORKS": "nonsense"}):
            detector = ThreatDetector()
        self.assertTrue(detector._private("10.0.0.5"))

    def test_configured_internal_range_suppresses_exfiltration(self):
        """The override must actually reach the exfiltration rule."""
        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"NEMOS_INTERNAL_NETWORKS": "203.0.113.0/24"}):
            detector = ThreatDetector(DetectionConfig(exfil_bytes=1_000_000))
        found = []
        for _ in range(30):
            found += detector.process(
                event("10.0.0.5", "203.0.113.7", 443, flags="PA", size=60_000))
        self.assertNotIn("DATA_EXFILTRATION_VOLUME", threats(found))
