"""TLS handshake fingerprinting.

Encrypted traffic is the blind spot a metadata-only sensor has, and the
handshake is the one part of a TLS session that is not encrypted. These tests
pin the two things that decide whether JA3 is useful or actively misleading.

**GREASE must be stripped.** RFC 8701 has clients inject reserved values into
their cipher, extension and curve lists on purpose, and Chrome picks different
ones on every connection. Hash the lists as they arrive and every browser
session produces a brand-new fingerprint -- so a fingerprint would never match
across two connections from the same software, which is the entire point of
having one. That property gets its own test because nothing else would catch
its loss: the parser would still return a hash, and the hash would still look
like a hash.

**A handshake is attacker-controlled input on the capture thread.** Every
length in it is a number chosen by whoever sent the packet. Malformed input
must return None, never raise and never loop, because an exception per packet
on that thread is dropped traffic.
"""

from __future__ import annotations

import os
import unittest

from nemos.detector import TLS_EXPECTED_PORTS, DetectionConfig, ThreatDetector
from nemos.models import TrafficEvent
from nemos.tls import (
    MAX_HANDSHAKE_BYTES,
    is_grease,
    looks_like_handshake,
    parse_hello,
)

# RFC 8701's full reserved set.
GREASE_VALUES = (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
                 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA)


def u16(value: int) -> bytes:
    return bytes([value >> 8, value & 0xFF])


def block16(body: bytes) -> bytes:
    return u16(len(body)) + body


def block8(body: bytes) -> bytes:
    return bytes([len(body)]) + body


def client_hello(*, grease: int = 0x0A0A, sni: str = "example.com",
                 ciphers: tuple[int, ...] = (0x1301, 0xC02B, 0x009C),
                 groups: tuple[int, ...] = (0x001D, 0x0017)) -> bytes:
    """A Chrome-shaped ClientHello: GREASE leading ciphers, extensions, groups."""
    suites = b"".join(u16(c) for c in ((grease,) + ciphers))
    extensions = u16(grease) + block16(b"")
    if sni:
        extensions += u16(0x0000) + block16(
            block16(bytes([0]) + block16(sni.encode())))
    extensions += u16(0x000A) + block16(
        block16(b"".join(u16(g) for g in ((grease,) + groups))))
    extensions += u16(0x000B) + block16(block8(bytes([0])))
    extensions += u16(0x0017) + block16(b"")

    body = (u16(0x0303) + os.urandom(32) + block8(os.urandom(32))
            + block16(suites) + block8(bytes([0])) + block16(extensions))
    handshake = bytes([1]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16]) + u16(0x0301) + block16(handshake)


def server_hello(cipher: int = 0x1301) -> bytes:
    body = (u16(0x0303) + os.urandom(32) + block8(b"") + u16(cipher) + bytes([0])
            + block16(u16(0x0017) + block16(b"")))
    handshake = bytes([2]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16]) + u16(0x0303) + block16(handshake)


class Grease(unittest.TestCase):
    def test_every_reserved_value_is_recognised(self):
        for value in GREASE_VALUES:
            with self.subTest(value=hex(value)):
                self.assertTrue(is_grease(value))

    def test_real_ciphers_and_extensions_are_not_mistaken_for_grease(self):
        # A false positive here silently deletes a real cipher from the
        # fingerprint, which would make NEMOS's hashes disagree with every
        # other JA3 implementation.
        for value in (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0x009C, 0x0035,
                      0x0000, 0x000A, 0x000B, 0x0017, 0x002B, 0xFF01):
            with self.subTest(value=hex(value)):
                self.assertFalse(is_grease(value))

    def test_a_fingerprint_survives_the_grease_changing_every_connection(self):
        """The property the whole feature rests on.

        Without stripping, the same browser produces a different fingerprint on
        every connection and JA3 tells you nothing.
        """
        prints = {parse_hello(client_hello(grease=g)).fingerprint()
                  for g in GREASE_VALUES}
        self.assertEqual(len(prints), 1, "GREASE is leaking into the fingerprint")

    def test_a_genuinely_different_client_gets_a_different_fingerprint(self):
        """Stripping GREASE must not flatten everything to one hash."""
        chrome = parse_hello(client_hello()).fingerprint()
        other = parse_hello(client_hello(ciphers=(0x0035, 0x002F))).fingerprint()
        self.assertNotEqual(chrome, other)


class Parsing(unittest.TestCase):
    def test_the_ja3_string_has_the_documented_shape(self):
        hello = parse_hello(client_hello())
        # Version,Ciphers,Extensions,Groups,PointFormats -- five comma fields.
        self.assertEqual(hello.ja3_string(), "771,4865-49195-156,0-10-11-23,29-23,0")
        self.assertEqual(len(hello.ja3_string().split(",")), 5)

    def test_the_server_side_is_fingerprinted_too(self):
        hello = parse_hello(server_hello())
        self.assertEqual(hello.kind, "server")
        self.assertEqual(len(hello.ja3_string().split(",")), 3)
        self.assertTrue(hello.fingerprint())

    def test_sni_is_extracted_and_does_not_change_the_fingerprint(self):
        """JA3 identifies the client software, not where it is going."""
        one = parse_hello(client_hello(sni="mail.example.com"))
        two = parse_hello(client_hello(sni="cdn.other.net"))
        self.assertEqual(one.server_name, "mail.example.com")
        self.assertEqual(two.server_name, "cdn.other.net")
        self.assertEqual(one.fingerprint(), two.fingerprint())

    def test_a_handshake_with_no_sni_simply_has_none(self):
        hello = parse_hello(client_hello(sni=""))
        self.assertEqual(hello.server_name, "")
        self.assertNotIn("sni", hello.as_dict())

    def test_the_version_is_reported_by_name(self):
        self.assertEqual(parse_hello(client_hello()).version_name, "TLS1.2")

    def test_a_handshake_is_recognised_by_its_record_header_not_its_port(self):
        """Keying on port 443 would miss every C2 channel that moved off it."""
        self.assertTrue(looks_like_handshake(client_hello()))
        self.assertFalse(looks_like_handshake(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        # Content type 23 is application data -- encrypted, and never parsed.
        self.assertFalse(looks_like_handshake(bytes([0x17]) + u16(0x0303) + block16(b"x" * 40)))


class HostileInput(unittest.TestCase):
    """Every length in a handshake is chosen by whoever sent the packet."""

    def test_malformed_input_returns_none_and_never_raises(self):
        good = client_hello()
        cases = {
            "empty": b"",
            "record header only": bytes([0x16]) + u16(0x0301),
            "truncated mid-handshake": good[:12],
            "length longer than the data": bytes([0x16]) + u16(0x0301) + u16(60000) + good[5:40],
            "application data": bytes([0x17]) + u16(0x0303) + block16(b"x" * 64),
            "random noise": os.urandom(400),
            "zero length record": bytes([0x16]) + u16(0x0301) + u16(0),
            "impossible version": bytes([0x16]) + u16(0x9999) + block16(b"\x01\x00\x00\x00"),
        }
        for name, payload in cases.items():
            with self.subTest(case=name):
                self.assertIsNone(parse_hello(payload))

    def test_every_truncation_of_a_valid_handshake_is_survivable(self):
        """Fuzzes the boundary the bounds checks exist for."""
        good = client_hello()
        for cut in range(len(good)):
            with self.subTest(length=cut):
                parse_hello(good[:cut])   # must not raise

    def test_a_declared_length_cannot_make_the_parser_read_past_the_data(self):
        good = client_hello()
        lying = bytes([0x16]) + u16(0x0301) + u16(0xFFFF) + good[5:]
        result = parse_hello(lying)
        # Either it parses what is genuinely there or it refuses; it must not
        # raise, and must not invent ciphers that were never sent.
        if result is not None:
            self.assertLessEqual(len(result.ciphers), 16)

    def test_only_a_bounded_prefix_is_ever_examined(self):
        padded = client_hello() + b"\x00" * (MAX_HANDSHAKE_BYTES * 4)
        self.assertIsNotNone(parse_hello(padded))

    def test_a_hostile_sni_cannot_carry_arbitrary_bytes_into_storage(self):
        """SNI reaches SQLite, the API and the console, so it is constrained."""
        for evil in ("a<script>b", "x\x00y", "hos\tname", "n\nl", "sp ace"):
            with self.subTest(sni=evil):
                hello = parse_hello(client_hello(sni=evil))
                self.assertEqual(hello.server_name, "",
                                 f"accepted a hostile SNI: {evil!r}")


class DetectionBehaviour(unittest.TestCase):
    JA3 = "51c64c77e60f3980eea90869b68c58a8"

    def event(self, source, destination, port, ja3=None, sni=""):
        metadata = {"ja3": ja3 or self.JA3, "tls_version": "TLS1.2"}
        if sni:
            metadata["sni"] = sni
        return TrafficEvent("2026-01-01T00:00:00+00:00", source, destination,
                            "TCP", 50000, port, 517, "PA", "eth0",
                            metadata=metadata)

    def drive(self, events):
        detector = ThreatDetector(DetectionConfig())
        found = []
        for when, event in events:
            found.extend(detector.process(event, "TCP", now=when))
        return detector, found

    def test_ordinary_browsing_produces_no_tls_finding(self):
        """One client, port 443, many sites -- the commonest traffic there is."""
        _, found = self.drive([
            (i * 2.0, self.event("192.168.1.50", f"93.184.216.{i}", 443,
                                 sni=f"site{i}.example.com"))
            for i in range(30)
        ])
        self.assertEqual([a for a in found if a.threat.startswith("TLS_")], [])

    def test_tls_to_an_external_host_on_a_non_tls_port_is_reported(self):
        _, found = self.drive([
            (i * 5.0, self.event("192.168.1.77", "203.0.113.200", 8080))
            for i in range(4)
        ])
        finding = next(a for a in found if a.threat == "TLS_ON_UNEXPECTED_PORT")
        self.assertEqual(finding.technique, "T1571")
        self.assertEqual(finding.evidence["port"], 8080)
        self.assertIn(self.JA3, finding.evidence["ja3"])

    def test_tls_on_an_odd_port_to_an_internal_host_is_not_reported(self):
        """Internal services on unusual ports are ordinary; the rule is about
        a channel leaving the network."""
        _, found = self.drive([
            (i * 5.0, self.event("192.168.1.77", "192.168.1.9", 8080))
            for i in range(8)
        ])
        self.assertEqual([a for a in found if a.threat == "TLS_ON_UNEXPECTED_PORT"], [])

    def test_the_expected_port_set_covers_the_common_tls_services(self):
        for port in (443, 993, 995, 465, 587, 636, 853, 8443):
            self.assertIn(port, TLS_EXPECTED_PORTS)

    def test_a_command_and_control_finding_carries_the_client_fingerprint(self):
        """The practical payoff: a JA3 can be pivoted on, a destination cannot."""
        _, found = self.drive([
            (i * 2.4, self.event("192.168.1.90", "203.0.113.77", 443,
                                 sni="cdn.example-lookalike.net"))
            for i in range(8)
        ])
        c2 = [a for a in found if a.category == "COMMAND_AND_CONTROL"]
        self.assertTrue(c2, "fixture produced no command-and-control finding")
        evidence = c2[0].evidence
        self.assertIn(self.JA3, evidence["ja3"])
        self.assertIn("cdn.example-lookalike.net", evidence["sni"])

    def test_enrichment_never_overwrites_what_the_rule_established(self):
        _, found = self.drive([
            (i * 2.4, self.event("192.168.1.91", "203.0.113.78", 443))
            for i in range(8)
        ])
        c2 = [a for a in found if a.category == "COMMAND_AND_CONTROL"]
        self.assertTrue(c2)
        # The beacon rule sets `destination` itself; enrichment must not clobber it.
        self.assertEqual(c2[0].evidence["destination"], "203.0.113.78")

    def test_fingerprint_diversity_is_evidence_and_never_its_own_finding(self):
        """It cannot earn a standalone confidence: behind NAT one address
        aggregates every host behind it and reaches any threshold honestly."""
        detector, found = self.drive([
            (i * 3.0, self.event("10.0.0.66", f"203.0.113.{i}", 443,
                                 ja3=f"{i:032x}", sni=f"c{i}.example.net"))
            for i in range(9)
        ])
        self.assertEqual([a for a in found if a.threat.startswith("TLS_FINGERPRINT")], [])
        evidence = detector.tls_evidence("10.0.0.66", now=30.0)
        self.assertEqual(evidence["distinct_fingerprints"], 9)
        self.assertIn("NAT", evidence["fingerprint_diversity"])

    def test_a_source_that_never_spoke_tls_has_no_tls_evidence(self):
        detector = ThreatDetector(DetectionConfig())
        self.assertEqual(detector.tls_evidence("192.168.1.1", now=1.0), {})

    def test_tracked_fingerprints_stay_bounded(self):
        """The fingerprint is attacker-chosen, so the map holding it is bounded."""
        config = DetectionConfig()
        detector, _ = self.drive([
            (float(i), self.event("10.0.0.99", "203.0.113.5", 443, ja3=f"{i:032x}"))
            for i in range(config.tls_max_tracked * 5)
        ])
        self.assertLessEqual(
            len(detector.tls["10.0.0.99"]["fingerprints"]), config.tls_max_tracked)

    def test_tracked_sources_stay_bounded(self):
        config = DetectionConfig()
        detector, _ = self.drive([
            (float(i), self.event(f"10.1.{i // 256}.{i % 256}", "203.0.113.5", 443))
            for i in range(config.max_sources + 40)
        ])
        self.assertLessEqual(len(detector.tls), config.max_sources)


if __name__ == "__main__":
    unittest.main()
