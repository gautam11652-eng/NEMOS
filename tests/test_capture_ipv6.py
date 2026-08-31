"""IPv6 must reach the detector, or every rule is blind to half the network.

The capture path dropped every IPv6 packet at ``haslayer(IP)``. Nothing failed
and nothing was logged -- the sensor simply reported no findings for v6
traffic, which is indistinguishable from a quiet network. On a dual-stack
segment an attacker bypassed all 27 rules by preferring the other address
family.

These tests are built on real scapy packets rather than hand-rolled fakes,
because the bug lived in exactly the gap between the two: the previous fake
packet in tests/test_capture.py could not represent an IPv6 layer at all, so
no test could have caught this.
"""

from __future__ import annotations

import unittest

from nemos.capture import NDP_TYPES, PacketCapture, icmpv6_layer, ndp_binding
from nemos.detector import DetectionConfig, ThreatDetector

scapy = None
try:  # pragma: no cover - exercised by the skip below
    from scapy.all import DNS, ICMP, IP, IPv6, TCP, UDP
    from scapy.layers.inet6 import (
        ICMPv6EchoRequest,
        ICMPv6ND_NA,
        ICMPv6ND_NS,
        ICMPv6NDOptDstLLAddr,
        ICMPv6NDOptSrcLLAddr,
        IPv6ExtHdrHopByHop,
    )
    scapy = True
except ImportError:  # pragma: no cover
    scapy = False


def parse(packet):
    if not scapy:
        return None, ""
    return PacketCapture._parse(packet, IP, TCP, UDP, ICMP, DNS, "eth0", IPv6)


@unittest.skipUnless(scapy, "scapy is not installed")
class IPv6ReachesTheDetector(unittest.TestCase):
    def test_a_v6_tcp_packet_is_parsed_not_dropped(self):
        event, ptype = parse(
            IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=40000, dport=443, flags="S"))
        self.assertIsNotNone(event, "IPv6 TCP was dropped by the capture path")
        self.assertEqual(ptype, "TCP")
        self.assertEqual(event.source, "2001:db8::1")
        self.assertEqual(event.destination, "2001:db8::2")
        self.assertEqual(event.destination_port, 443)
        self.assertEqual(event.flags, "S")

    def test_a_v6_udp_packet_is_parsed(self):
        event, ptype = parse(
            IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=40000, dport=161))
        self.assertIsNotNone(event)
        self.assertEqual(ptype, "UDP")
        self.assertEqual(event.destination_port, 161)

    def test_v6_dns_is_recognised_as_dns_not_generic_udp(self):
        event, ptype = parse(
            IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=40000, dport=53) / DNS())
        self.assertEqual(ptype, "DNS")
        self.assertEqual(event.protocol, "DNS")

    def test_icmpv6_echo_shares_the_icmp_rules(self):
        event, ptype = parse(
            IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest())
        self.assertEqual(ptype, "ICMP",
                         "ICMPv6 echo must reach the ICMP flood and sweep rules")

    def test_v6_records_its_address_family(self):
        event, _ = parse(IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP())
        self.assertEqual(event.metadata.get("ip_version"), 6)

    def test_v4_metadata_is_unchanged(self):
        event, _ = parse(IP(src="10.0.0.1", dst="10.0.0.2") / TCP())
        self.assertEqual(event.metadata, {})

    def test_a_packet_with_neither_family_is_still_ignored(self):
        from scapy.all import Ether
        event, ptype = parse(Ether())
        self.assertIsNone(event)
        self.assertEqual(ptype, "")


@unittest.skipUnless(scapy, "scapy is not installed")
class NeighbourDiscoveryIsNotAPingFlood(unittest.TestCase):
    """NDP is IPv6's ARP: constant, benign, and not ICMP traffic.

    Counting it as ICMP would report a permanent ping flood on every healthy
    dual-stack segment -- a false positive introduced by the very change that
    added v6 support.
    """

    def test_neighbour_solicitation_is_not_counted_as_icmp(self):
        _, ptype = parse(IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_NS(tgt="fe80::2"))
        self.assertEqual(ptype, "NDP")

    def test_neighbour_advertisement_is_not_counted_as_icmp(self):
        _, ptype = parse(IPv6(src="fe80::2", dst="fe80::1") / ICMPv6ND_NA(tgt="fe80::2"))
        self.assertEqual(ptype, "NDP")

    def test_ndp_traffic_is_still_recorded_not_discarded(self):
        event, _ = parse(IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_NS(tgt="fe80::2"))
        self.assertIsNotNone(event, "NDP is real traffic and must still be accounted for")
        self.assertEqual(event.protocol, "NDP")

    def test_every_ndp_type_is_classified_the_same_way(self):
        self.assertEqual(NDP_TYPES, frozenset({133, 134, 135, 136, 137}))


@unittest.skipUnless(scapy, "scapy is not installed")
class ExtensionHeadersDoNotHideICMPv6(unittest.TestCase):
    def test_icmpv6_is_found_behind_a_hop_by_hop_header(self):
        packet = (IPv6(src="2001:db8::1", dst="2001:db8::2")
                  / IPv6ExtHdrHopByHop() / ICMPv6EchoRequest())
        self.assertIsNotNone(icmpv6_layer(packet))
        _, ptype = parse(packet)
        self.assertEqual(ptype, "ICMP",
                         "an extension header must not let ICMPv6 evade classification")

    def test_a_v6_packet_without_icmpv6_yields_none(self):
        self.assertIsNone(icmpv6_layer(IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP()))

    def test_a_v4_packet_yields_none(self):
        self.assertIsNone(icmpv6_layer(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()))


@unittest.skipUnless(scapy, "scapy is not installed")
class RulesFireOnIPv6Sources(unittest.TestCase):
    """The point of the fix: detection, not just parsing."""

    def test_a_v6_port_scan_is_detected(self):
        detector = ThreatDetector(DetectionConfig(port_scan=8, window=10))
        alerts = []
        for port in range(1000, 1020):
            event, ptype = parse(
                IPv6(src="2001:db8::dead", dst="2001:db8::1")
                / TCP(sport=40000, dport=port, flags="S"))
            alerts.extend(detector.process(event, ptype))
        threats = {alert.threat for alert in alerts}
        self.assertIn("PORT_SCAN", threats,
                      f"a v6 port scan produced no scan finding: {threats}")

    def test_a_v6_source_is_classified_external_when_it_is_global(self):
        detector = ThreatDetector(DetectionConfig())
        # 2001:db8:: is documentation space and deliberately outside the
        # default internal ranges (::1/128, fc00::/7, fe80::/10).
        self.assertFalse(detector._private("2001:db8::1"))

    def test_v6_unique_local_and_link_local_are_internal(self):
        detector = ThreatDetector(DetectionConfig())
        self.assertTrue(detector._private("fd00::1"))
        self.assertTrue(detector._private("fe80::1"))
        self.assertTrue(detector._private("::1"))

    def test_a_v6_icmp_sweep_is_detected(self):
        detector = ThreatDetector(DetectionConfig(icmp_sweep=12, window=10))
        alerts = []
        for host in range(1, 30):
            event, ptype = parse(
                IPv6(src="2001:db8::beef", dst=f"2001:db8::{host:x}") / ICMPv6EchoRequest())
            alerts.extend(detector.process(event, ptype))
        threats = {alert.threat for alert in alerts}
        self.assertTrue(threats, "a v6 ICMP sweep produced no finding at all")


@unittest.skipUnless(scapy, "scapy is not installed")
class NDPSpoofingIsDetected(unittest.TestCase):
    """IPv6's equivalent of ARP cache poisoning.

    NEMOS detected forged ARP replies but was blind to the identical attack
    over Neighbour Discovery, which is what an adversary on a v6 segment
    actually uses (parasite6 and similar send unsolicited advertisements).
    """

    def binding(self, packet):
        return ndp_binding(packet[IPv6], icmpv6_layer(packet))

    def test_an_advertisement_binds_its_target_address(self):
        packet = (IPv6(src="fe80::2", dst="fe80::1")
                  / ICMPv6ND_NA(tgt="2001:db8::99")
                  / ICMPv6NDOptDstLLAddr(lladdr="aa:bb:cc:dd:ee:ff"))
        claimed, mac = self.binding(packet)
        self.assertEqual(claimed, "2001:db8::99",
                         "an advertisement speaks for its target, not its sender")
        self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")

    def test_a_solicitation_binds_its_own_source(self):
        packet = (IPv6(src="fe80::5", dst="ff02::1")
                  / ICMPv6ND_NS(tgt="fe80::1")
                  / ICMPv6NDOptSrcLLAddr(lladdr="11:22:33:44:55:66"))
        claimed, mac = self.binding(packet)
        self.assertEqual(claimed, "fe80::5")
        self.assertEqual(mac, "11:22:33:44:55:66")

    def test_duplicate_address_detection_binds_nothing(self):
        # A solicitation from :: is DAD -- the sender is asking whether an
        # address is free, not claiming it. Treating that as a binding would
        # alert on entirely normal address configuration.
        packet = (IPv6(src="::", dst="ff02::1")
                  / ICMPv6ND_NS(tgt="fe80::1")
                  / ICMPv6NDOptSrcLLAddr(lladdr="11:22:33:44:55:66"))
        self.assertEqual(self.binding(packet), (None, None))

    def test_an_advertisement_without_a_link_layer_option_binds_nothing(self):
        packet = IPv6(src="fe80::2", dst="fe80::1") / ICMPv6ND_NA(tgt="2001:db8::99")
        self.assertEqual(self.binding(packet), (None, None))

    def test_an_echo_request_is_not_a_binding(self):
        packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()
        self.assertEqual(self.binding(packet), (None, None))

    def test_the_binding_reaches_the_parsed_event(self):
        packet = (IPv6(src="fe80::2", dst="fe80::1")
                  / ICMPv6ND_NA(tgt="2001:db8::99")
                  / ICMPv6NDOptDstLLAddr(lladdr="aa:bb:cc:dd:ee:ff"))
        event, ptype = parse(packet)
        self.assertEqual(ptype, "NDP")
        self.assertEqual(event.metadata.get("claimed"), "2001:db8::99")
        self.assertEqual(event.metadata.get("mac"), "aa:bb:cc:dd:ee:ff")

    def test_a_changed_binding_raises_a_finding(self):
        detector = ThreatDetector(DetectionConfig())
        self.assertIsNone(detector.observe_ndp("2001:db8::99", "aa:bb:cc:dd:ee:ff"))
        alert = detector.observe_ndp("2001:db8::99", "00:11:22:33:44:55")
        self.assertIsNotNone(alert, "a neighbour cache takeover produced no finding")
        self.assertEqual(alert.threat, "NDP_MAPPING_CHANGE")
        self.assertEqual(alert.technique, "T1557")
        self.assertEqual(alert.evidence["old_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(alert.evidence["new_mac"], "00:11:22:33:44:55")

    def test_a_stable_binding_stays_quiet(self):
        detector = ThreatDetector(DetectionConfig())
        detector.observe_ndp("2001:db8::99", "aa:bb:cc:dd:ee:ff")
        for _ in range(5):
            self.assertIsNone(detector.observe_ndp("2001:db8::99", "AA:BB:CC:DD:EE:FF"),
                              "case alone must not read as a takeover")

    def test_arp_and_ndp_share_one_bounded_map(self):
        detector = ThreatDetector(DetectionConfig(max_sources=64))
        for index in range(500):
            detector.observe_ndp(f"2001:db8::{index:x}", "aa:bb:cc:dd:ee:ff")
            detector.observe_arp(f"10.0.0.{index % 254}", "aa:bb:cc:dd:ee:ff")
        self.assertLessEqual(len(detector.arp), 65)

    def test_arp_findings_are_unchanged_by_the_refactor(self):
        detector = ThreatDetector(DetectionConfig())
        detector.observe_arp("10.0.0.5", "aa:bb:cc:dd:ee:ff")
        alert = detector.observe_arp("10.0.0.5", "00:11:22:33:44:55")
        self.assertEqual(alert.threat, "ARP_MAPPING_CHANGE")
        self.assertEqual(alert.technique, "T1557.002")
        self.assertIn("ARP mapping changed", alert.reason)


if __name__ == "__main__":
    unittest.main()
