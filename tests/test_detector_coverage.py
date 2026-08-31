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
        # Port 445 is SMB, so the sub-technique is what the evidence supports.
        self.assertEqual(alerts[0].technique, "T1021.002")

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


class TechniqueMappingTests(unittest.TestCase):
    """ATT&CK claims must follow the evidence, not the threat name."""

    def test_external_scan_is_reconnaissance_not_discovery(self):
        # ATT&CK separates pre-compromise scanning from outside (T1595) from
        # post-compromise service discovery from inside (T1046).
        detector = ThreatDetector()
        found = []
        for port in range(100, 110):
            found += detector.process(event("203.0.113.9", "10.0.0.9", port))
        scan = next(a for a in found if a.threat == "PORT_SCAN")
        self.assertEqual(scan.technique, "T1595")
        self.assertEqual(scan.evidence["source_position"], "external")

    def test_internal_scan_is_service_discovery(self):
        detector = ThreatDetector()
        found = []
        for port in range(100, 110):
            found += detector.process(event("10.0.0.5", "10.0.0.9", port))
        scan = next(a for a in found if a.threat == "PORT_SCAN")
        self.assertEqual(scan.technique, "T1046")
        self.assertEqual(scan.evidence["source_position"], "internal")

    def test_host_enumeration_is_remote_system_discovery(self):
        detector = ThreatDetector()
        found = []
        for host in range(10, 45):
            found += detector.process(event("10.0.0.5", f"10.0.0.{host}", 80))
        fanout = next(a for a in found if a.threat == "NETWORK_FANOUT")
        self.assertEqual(fanout.technique, "T1018")

    def test_lateral_movement_names_the_service_sub_technique(self):
        for port, technique, service in (
            (3389, "T1021.001", "RDP"),
            (445, "T1021.002", "SMB"),
            (22, "T1021.004", "SSH"),
            (5900, "T1021.005", "VNC"),
            (5985, "T1021.006", "WinRM"),
        ):
            detector = ThreatDetector()
            found = []
            for host in range(10, 20):
                found += detector.process(event("10.0.0.5", f"10.0.0.{host}", port))
            alert = next(a for a in found if a.threat == "LATERAL_MOVEMENT")
            self.assertEqual(alert.technique, technique, f"port {port}")
            self.assertEqual(alert.evidence["service"], service)

    def test_unknown_admin_port_falls_back_to_the_parent(self):
        # 135 is an admin port with no dedicated sub-technique. Claiming a
        # specific one would be a guess.
        detector = ThreatDetector()
        found = []
        for host in range(10, 20):
            found += detector.process(event("10.0.0.5", f"10.0.0.{host}", 135))
        alert = next(a for a in found if a.threat == "LATERAL_MOVEMENT")
        self.assertEqual(alert.technique, "T1021")


class PasswordSprayingTests(unittest.TestCase):
    def test_spraying_detected(self):
        detector = ThreatDetector()
        found = []
        for host in range(10, 25):
            for _ in range(3):
                found += detector.process(event("10.0.0.5", f"10.0.0.{host}", 22))
        alerts = [a for a in found if a.threat == "PASSWORD_SPRAYING"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1110.003")

    def test_concentrated_guessing_is_not_spraying(self):
        # Many attempts on one host is brute force; the two must not collide.
        detector = ThreatDetector()
        found = []
        for _ in range(30):
            found += detector.process(event("10.0.0.5", "10.0.0.9", 22))
        self.assertNotIn("PASSWORD_SPRAYING", threats(found))
        self.assertIn("CREDENTIAL_BRUTE_FORCE", threats(found))

    def test_brute_force_is_password_guessing(self):
        detector = ThreatDetector()
        found = []
        for _ in range(25):
            found += detector.process(event("10.0.0.5", "10.0.0.9", 22))
        alert = next(a for a in found if a.threat == "CREDENTIAL_BRUTE_FORCE")
        self.assertEqual(alert.technique, "T1110.001")


class IcmpTunnelingTests(unittest.TestCase):
    def test_large_icmp_detected(self):
        detector = ThreatDetector()
        found = []
        for _ in range(15):
            found += detector.process(
                event("10.0.0.5", "203.0.113.7", None, protocol="ICMP", flags="", size=900))
        alerts = [a for a in found if a.threat == "ICMP_TUNNELING_PATTERN"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1095")

    def test_ordinary_ping_does_not_trigger(self):
        detector = ThreatDetector()
        found = []
        for _ in range(15):
            found += detector.process(
                event("10.0.0.5", "203.0.113.7", None, protocol="ICMP", flags="", size=74))
        self.assertNotIn("ICMP_TUNNELING_PATTERN", threats(found))


class EndpointDosTests(unittest.TestCase):
    def test_service_flood_detected(self):
        detector = ThreatDetector(DetectionConfig(service_dos=50))
        found = []
        for _ in range(60):
            found += detector.process(event("10.0.0.5", "10.0.0.9", 443, flags="S"))
        alerts = [a for a in found if a.threat == "SERVICE_DENIAL_OF_SERVICE"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1499")
        self.assertEqual(alerts[0].evidence["service_port"], 443)

    def test_spread_traffic_is_not_endpoint_dos(self):
        detector = ThreatDetector(DetectionConfig(service_dos=50))
        found = []
        for i in range(60):
            found += detector.process(event("10.0.0.5", f"10.0.0.{i % 30 + 10}", 443))
        self.assertNotIn("SERVICE_DENIAL_OF_SERVICE", threats(found))


class AmplificationTests(unittest.TestCase):
    def _flood(self, sport):
        detector = ThreatDetector(DetectionConfig(amplification_packets=30))
        found = []
        for _ in range(40):
            traffic = TrafficEvent(
                "2026-01-01T00:00:00Z", "10.0.0.5", "203.0.113.7", "UDP",
                source_port=sport, destination_port=40000, packet_size=1400, flags="")
            found += detector.process(traffic)
        return found

    def test_reflected_dns_detected(self):
        alerts = [a for a in self._flood(53) if a.threat == "REFLECTION_AMPLIFICATION"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1498.002")

    def test_evidence_notes_the_source_is_spoofed(self):
        alert = next(a for a in self._flood(123) if a.threat == "REFLECTION_AMPLIFICATION")
        self.assertIn("spoofed", alert.evidence["note"])

    def test_ordinary_client_port_does_not_trigger(self):
        self.assertNotIn("REFLECTION_AMPLIFICATION", threats(self._flood(51234)))


class IngressTransferTests(unittest.TestCase):
    def test_inbound_bulk_transfer_detected(self):
        detector = ThreatDetector(DetectionConfig(ingress_bytes=1_000_000))
        found = []
        for _ in range(30):
            found += detector.process(
                event("203.0.113.7", "10.0.0.9", 443, flags="PA", size=60_000))
        alerts = [a for a in found if a.threat == "INGRESS_TOOL_TRANSFER"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1105")

    def test_internal_to_internal_transfer_does_not_trigger(self):
        detector = ThreatDetector(DetectionConfig(ingress_bytes=1_000_000))
        found = []
        for _ in range(30):
            found += detector.process(
                event("10.0.0.5", "10.0.0.9", 445, flags="PA", size=60_000))
        self.assertNotIn("INGRESS_TOOL_TRANSFER", threats(found))


class ExfiltrationOverC2Tests(unittest.TestCase):
    def test_transfer_to_a_known_beacon_target_is_over_c2(self):
        """The correlation that makes this worth separating from T1048."""
        detector = ThreatDetector(DetectionConfig(exfil_bytes=1_000_000))
        clock = 1000.0
        # Establish the beacon first.
        for _ in range(8):
            clock += 30.0
            detector.process(event("10.0.0.5", "203.0.113.7", 8443, flags="PA"), now=clock)
        self.assertIn(("10.0.0.5", "203.0.113.7"), detector.beacon_targets)

        found = []
        for _ in range(30):
            clock += 0.1
            found += detector.process(
                event("10.0.0.5", "203.0.113.7", 8443, flags="PA", size=60_000), now=clock)
        alerts = [a for a in found if a.threat == "DATA_EXFILTRATION_OVER_C2"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1041")
        self.assertTrue(alerts[0].evidence["over_beacon_channel"])

    def test_transfer_to_an_unrelated_host_stays_generic(self):
        detector = ThreatDetector(DetectionConfig(exfil_bytes=1_000_000))
        found = []
        for _ in range(30):
            found += detector.process(
                event("10.0.0.5", "203.0.113.99", 443, flags="PA", size=60_000))
        alerts = [a for a in found if a.threat == "DATA_EXFILTRATION_VOLUME"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1048")

    def test_beacon_target_table_is_bounded(self):
        detector = ThreatDetector(DetectionConfig(max_sources=4))
        clock = 1000.0
        for i in range(400):
            for _ in range(7):
                clock += 3.0
                detector.process(event("10.0.0.5", f"203.0.113.{i % 200}", 8443), now=clock)
        self.assertLessEqual(len(detector.beacon_targets), detector.cfg.max_sources * 4)


class NonStandardPortTests(unittest.TestCase):
    def test_sustained_high_port_traffic_detected(self):
        detector = ThreatDetector()
        found = []
        for _ in range(45):
            found += detector.process(event("10.0.0.5", "203.0.113.7", 48291, flags="PA"))
        alerts = [a for a in found if a.threat == "NON_STANDARD_PORT_TRAFFIC"]
        self.assertTrue(alerts)
        self.assertEqual(alerts[0].technique, "T1571")

    def test_confidence_stays_low_because_the_signal_is_weak(self):
        detector = ThreatDetector()
        found = []
        for _ in range(45):
            found += detector.process(event("10.0.0.5", "203.0.113.7", 48291, flags="PA"))
        alert = next(a for a in found if a.threat == "NON_STANDARD_PORT_TRAFFIC")
        self.assertLess(alert.confidence, 65)
        self.assertIn("not a", alert.evidence["note"])

    def test_standard_https_does_not_trigger(self):
        detector = ThreatDetector()
        found = []
        for _ in range(45):
            found += detector.process(event("10.0.0.5", "203.0.113.7", 443, flags="PA"))
        self.assertNotIn("NON_STANDARD_PORT_TRAFFIC", threats(found))


class CatalogIntegrityTests(unittest.TestCase):
    def test_catalog_contains_nothing_aspirational(self):
        """Every catalog entry must be emitted, or explicitly marked legacy.

        A catalog listing techniques NEMOS cannot evidence would overstate its
        coverage -- exactly the failure mode the project exists to avoid.
        """
        import re
        from pathlib import Path
        from nemos.attack import LEGACY_TECHNIQUES

        source = Path("nemos/detector.py").read_text()
        emitted = set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"', source))
        unreachable = set(TECHNIQUES) - emitted - set(LEGACY_TECHNIQUES)
        self.assertEqual(unreachable, set())

    def test_every_technique_has_a_url_matching_its_id(self):
        for tid, technique in TECHNIQUES.items():
            self.assertTrue(technique.url.startswith("https://attack.mitre.org/techniques/"))
            self.assertIn(tid.replace(".", "/"), technique.url)

    def test_kill_chain_covers_every_catalog_tactic(self):
        """A tactic with no chain stage would render findings nowhere."""
        from pathlib import Path
        js = Path("nemos/static/app.js").read_text()
        for technique in TECHNIQUES.values():
            first = technique.tactic.split("/")[0].strip().split()[0].lower()
            self.assertIn(first, js.lower(), f"{technique.tactic} has no chain stage")


class BidirectionalInterfaceTests(unittest.TestCase):
    """Traffic as seen on a normal NIC, not a one-way tap.

    NEMOS is designed around unidirectional flows, but most people will point
    it at an ordinary interface, where both directions are visible. Capturing
    on a real NIC showed the consequence: a web server answering several client
    connections was reported as a vertical PORT_SCAN, because its replies land
    on many ephemeral ports of this host. Every characteristic was the inverse
    of a scan -- all destination ports ephemeral, syn_ratio 0.0, one source
    port, one destination -- and it would have fired against every busy server
    on the network, continuously.
    """

    def _server_replies(self, count=12):
        """A service answering client connections from many ephemeral ports."""
        detector = ThreatDetector()
        found = []
        for i in range(count):
            found += detector.process(TrafficEvent(
                "2026-01-01T00:00:00Z", "203.0.113.10", "10.0.0.5", "TCP",
                source_port=443, destination_port=40000 + i * 7,
                packet_size=1400, flags="PA"))
        return found

    def test_server_replies_are_not_a_port_scan(self):
        self.assertNotIn("PORT_SCAN", threats(self._server_replies()))

    def test_a_real_scan_from_a_high_source_port_still_fires(self):
        """The guard must not blind the detector to actual scanning."""
        detector = ThreatDetector()
        found = []
        for port in range(20, 40):
            found += detector.process(TrafficEvent(
                "2026-01-01T00:00:00Z", "203.0.113.10", "10.0.0.5", "TCP",
                source_port=54321, destination_port=port,
                packet_size=60, flags="S"))
        self.assertIn("PORT_SCAN", threats(found))

    def test_syn_probes_to_ephemeral_ports_still_count(self):
        """Only acknowledged replies are excluded, never probes."""
        detector = ThreatDetector()
        found = []
        for i in range(12):
            found += detector.process(TrafficEvent(
                "2026-01-01T00:00:00Z", "203.0.113.10", "10.0.0.5", "TCP",
                source_port=443, destination_port=40000 + i * 7,
                packet_size=60, flags="S"))
        self.assertIn("PORT_SCAN", threats(found),
                      "a SYN sweep was excluded as if it were reply traffic")

    def test_replies_from_a_high_source_port_still_count(self):
        """Exclusion requires a service source port, not merely an ACK."""
        detector = ThreatDetector()
        found = []
        for i in range(12):
            found += detector.process(TrafficEvent(
                "2026-01-01T00:00:00Z", "203.0.113.10", "10.0.0.5", "TCP",
                source_port=51000, destination_port=40000 + i * 7,
                packet_size=60, flags="PA"))
        self.assertIn("PORT_SCAN", threats(found))

    def test_udp_scanning_is_unaffected(self):
        detector = ThreatDetector()
        found = []
        for port in range(100, 120):
            found += detector.process(TrafficEvent(
                "2026-01-01T00:00:00Z", "203.0.113.10", "10.0.0.5", "UDP",
                source_port=40000, destination_port=port, packet_size=60, flags=""))
        self.assertTrue({"PORT_SCAN", "UDP_PORT_SCAN"} & threats(found))


class ServiceBurstCountsConnectionsTests(unittest.TestCase):
    """The rule is named for connections; it was counting packets.

    A single TLS session is dozens of packets, so four ordinary HTTPS requests
    crossed a threshold meant to describe a burst of forty connections. Seen on
    a real interface: browsing tripped it.
    """

    def test_a_few_conversations_do_not_trip_it(self):
        detector = ThreatDetector()
        found = []
        for session in range(4):
            for _ in range(30):          # 120 packets, only 4 connections
                found += detector.process(TrafficEvent(
                    "2026-01-01T00:00:00Z", "10.0.0.5", "203.0.113.7", "TCP",
                    source_port=40000 + session, destination_port=443,
                    packet_size=1400, flags="PA"))
        self.assertNotIn("SERVICE_CONNECTION_BURST", threats(found))

    def test_many_connection_attempts_still_trip_it(self):
        detector = ThreatDetector()
        found = []
        for i in range(45):
            found += detector.process(TrafficEvent(
                "2026-01-01T00:00:00Z", "10.0.0.5", f"10.0.0.{i % 20 + 10}", "TCP",
                source_port=40000 + i, destination_port=443,
                packet_size=60, flags="S"))
        self.assertIn("SERVICE_CONNECTION_BURST", threats(found))

    def test_the_count_reported_is_connections(self):
        detector = ThreatDetector()
        found = []
        for i in range(45):
            for _ in range(3):           # each connection sends several packets
                found += detector.process(TrafficEvent(
                    "2026-01-01T00:00:00Z", "10.0.0.5", f"10.0.0.{i % 20 + 10}", "TCP",
                    source_port=40000 + i, destination_port=443,
                    packet_size=60, flags="S" if _ == 0 else "PA"))
        alert = next(a for a in found if a.threat == "SERVICE_CONNECTION_BURST")
        self.assertLessEqual(alert.evidence["service_connections"], 45,
                             "packets are still being counted as connections")
