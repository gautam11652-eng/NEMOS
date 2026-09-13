"""Tests for the capture-file replay path.

The properties that matter are not "does it print a table":

- the parser under test is the *live* one, so a drift between replay and
  capture is impossible by construction rather than by discipline;
- the detector's clock comes from the packets. This is the whole reason the
  tool exists: replaying an hour of traffic in a second puts every packet in
  one window and manufactures findings, and a test has to be able to catch a
  regression that reintroduces that;
- real captures contain packets that do not parse, and those are counted and
  reported rather than silently dropped.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "tools"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from collections import Counter  # noqa: E402

from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402

# Both MAC addresses are pinned on every frame. An Ether() without an explicit
# dst makes wrpcap resolve it by ARP on the real network -- two seconds of
# timeout per packet, and an outbound probe from a unit test.
LOCAL = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}

from nemos.capture import PacketCapture  # noqa: E402
from nemos.detector import DetectionConfig  # noqa: E402
from tools import replay_pcap as R  # noqa: E402

CONF = DetectionConfig.from_env()


def sweep(ports, start=1_700_000_000.0, step=0.05, src="192.0.2.10",
          dst="192.0.2.20"):
    """A vertical sweep whose packets carry explicit capture times."""
    out = []
    for i, port in enumerate(ports):
        pkt = Ether(**LOCAL) / IP(src=src, dst=dst) / TCP(sport=40000 + i, dport=port,
                                                   flags="S")
        pkt.time = start + i * step
        out.append(pkt)
    return out


def write(packets, directory, name="c.pcap"):
    path = Path(directory) / name
    wrpcap(str(path), packets)
    return path


class ParserSeamTests(unittest.TestCase):
    """`when` exists so replay does not need its own parser."""

    def test_parse_stamps_the_supplied_time(self):
        pkt = Ether(**LOCAL) / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=80)
        from scapy.all import DNS, IPv6
        event, ptype = PacketCapture._parse(
            pkt, IP, TCP, UDP, ICMP, DNS, "eth0", IPv6, "2020-01-01T00:00:00+00:00")
        self.assertEqual(event.timestamp, "2020-01-01T00:00:00+00:00")
        self.assertEqual(ptype, "TCP")

    def test_parse_still_stamps_now_when_not_given_one(self):
        """The live capture path passes no time and must be unaffected."""
        pkt = Ether(**LOCAL) / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=80)
        from scapy.all import DNS, IPv6
        event, _ = PacketCapture._parse(pkt, IP, TCP, UDP, ICMP, DNS, "", IPv6)
        self.assertTrue(event.timestamp)
        self.assertNotEqual(event.timestamp, "")

    def test_arp_parses_through_the_same_seam(self):
        pkt = Ether(**LOCAL) / ARP(psrc="192.0.2.1", pdst="192.0.2.2",
                            hwsrc="00:11:22:33:44:55")
        event, ptype = PacketCapture._parse_arp(pkt, ARP, "eth0", "T")
        self.assertEqual((ptype, event.timestamp, event.protocol),
                         ("ARP", "T", "ARP"))
        self.assertEqual(event.metadata["mac"], "00:11:22:33:44:55")

    def test_a_non_arp_packet_is_not_an_arp_event(self):
        pkt = Ether(**LOCAL) / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=80)
        self.assertEqual(PacketCapture._parse_arp(pkt, ARP, ""), (None, ""))


class ReadingTests(unittest.TestCase):
    def test_it_reads_what_was_written(self):
        with TemporaryDirectory() as d:
            path = write(sweep(range(20, 32)), d)
            stats = Counter()
            events = list(R.read(path, stats))
        self.assertEqual(len(events), 12)
        self.assertEqual(stats["read"], 12)
        self.assertEqual(stats["parsed_TCP"], 12)
        self.assertEqual(stats["malformed"], 0)

    def test_the_event_carries_the_packet_time_not_the_wall_clock(self):
        with TemporaryDirectory() as d:
            path = write(sweep([80], start=1_600_000_000.0), d)
            (when, event, _), = list(R.read(path, Counter()))
        self.assertAlmostEqual(when, 1_600_000_000.0, places=3)
        self.assertTrue(event.timestamp.startswith("2020-09-13"))

    def test_non_ip_traffic_is_counted_separately_not_as_a_failure(self):
        with TemporaryDirectory() as d:
            path = write([Ether(**LOCAL) / Raw(b"\x00" * 40)], d)
            stats = Counter()
            self.assertEqual(list(R.read(path, stats)), [])
        self.assertEqual(stats["not_ip"], 1)
        self.assertEqual(stats["malformed"], 0)

    def test_out_of_order_packets_are_counted(self):
        """A reversed clock breaks the window assumption, so it is reported."""
        packets = sweep(range(20, 24))
        packets[2].time = packets[0].time - 60
        with TemporaryDirectory() as d:
            path = write(packets, d)
            stats = Counter()
            list(R.read(path, stats))
        self.assertEqual(stats["out_of_order"], 1)

    def test_limit_stops_early_and_says_so(self):
        with TemporaryDirectory() as d:
            path = write(sweep(range(20, 40)), d)
            stats = Counter()
            events = list(R.read(path, stats, limit=5))
        self.assertEqual(len(events), 5)
        self.assertTrue(stats["truncated_by_limit"])


class ClockTests(unittest.TestCase):
    """The property the tool exists for."""

    SLOW = [1_700_000_000.0 + i * 13.0 for i in range(27)]

    def test_traffic_below_the_rule_raises_nothing_on_its_own_clock(self):
        """27 ports at one per 13s is 1 per window, far under port_scan=8."""
        packets = []
        for i, when in enumerate(self.SLOW):
            pkt = Ether(**LOCAL) / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
                sport=40000 + i, dport=9000 + i, flags="S")
            pkt.time = when
            packets.append(pkt)
        with TemporaryDirectory() as d:
            findings, _, span = R.replay(write(packets, d), CONF)
        self.assertEqual(findings, [], "a paced sweep must not look like a scan")
        self.assertAlmostEqual(span[2], 26 * 13.0, places=1)

    def test_the_same_packets_on_a_wall_clock_manufacture_a_finding(self):
        """This is the regression the packet clock prevents. If this ever stops
        firing, the guard below it has stopped being load-bearing."""
        from nemos.detector import ThreatDetector
        packets = []
        for i, when in enumerate(self.SLOW):
            pkt = Ether(**LOCAL) / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(
                sport=40000 + i, dport=9000 + i, flags="S")
            pkt.time = when
            packets.append(pkt)
        with TemporaryDirectory() as d:
            path = write(packets, d)
            detector = ThreatDetector(CONF)
            fired = [a for _, e, p in R.read(path, Counter())
                     for a in detector.process(e, p)]   # no now= : wall clock
        self.assertTrue(fired, "expected the compressed replay to fire")
        self.assertIn("PORT_SCAN", {a.threat for a in fired})

    def test_a_real_scan_is_still_detected_on_the_packet_clock(self):
        """The clock must not be so conservative that nothing ever fires."""
        with TemporaryDirectory() as d:
            path = write(sweep(range(20, 60), step=0.05), d)
            findings, _, _ = R.replay(path, CONF)
        self.assertTrue(findings)
        self.assertIn("PORT_SCAN", {a.threat for _, a in findings})


class ScheduleTests(unittest.TestCase):
    def schedule(self, directory, attacks):
        path = Path(directory) / "s.json"
        path.write_text(json.dumps({"attacks": attacks}))
        return path

    def test_a_naive_timestamp_is_read_as_utc(self):
        with TemporaryDirectory() as d:
            path = self.schedule(d, [{"label": "x", "start": "2017-07-04T09:00:00",
                                      "end": "2017-07-04T10:00:00"}])
            attack, = R.load_schedule(path)
        self.assertEqual(attack.end - attack.start, 3600.0)

    def test_a_backwards_window_is_rejected(self):
        with TemporaryDirectory() as d:
            path = self.schedule(d, [{"label": "x", "start": 100, "end": 50}])
            with self.assertRaises(SystemExit):
                R.load_schedule(path)

    def test_a_missing_key_names_itself(self):
        with TemporaryDirectory() as d:
            path = self.schedule(d, [{"label": "x", "start": 1}])
            with self.assertRaises(SystemExit) as ctx:
                R.load_schedule(path)
        self.assertIn("end", str(ctx.exception))

    def test_an_empty_schedule_is_rejected_rather_than_scoring_everything_wrong(self):
        with TemporaryDirectory() as d:
            path = self.schedule(d, [])
            with self.assertRaises(SystemExit):
                R.load_schedule(path)


class ScoringTests(unittest.TestCase):
    class Fake:
        def __init__(self, threat, source):
            self.threat, self.source = threat, source

    def test_a_finding_inside_its_window_is_a_true_positive(self):
        attacks = [R.Attack("scan", 100, 200, {"192.0.2.10"}, set())]
        out = R.score([(150, self.Fake("PORT_SCAN", "192.0.2.10"))], attacks)
        self.assertEqual(out["findings_in_a_labelled_window"], 1)
        self.assertEqual(out["finding_precision"], 1.0)
        self.assertEqual(out["window_recall"], 1.0)

    def test_the_right_time_but_the_wrong_source_is_not_a_hit(self):
        """Otherwise any finding during a busy window scores as a catch."""
        attacks = [R.Attack("scan", 100, 200, {"192.0.2.10"}, set())]
        out = R.score([(150, self.Fake("PORT_SCAN", "198.51.100.7"))], attacks)
        self.assertEqual(out["findings_outside_every_window"], 1)
        self.assertEqual(out["window_recall"], 0.0)

    def test_an_unnamed_source_set_matches_any_source(self):
        attacks = [R.Attack("scan", 100, 200, set(), set())]
        out = R.score([(150, self.Fake("PORT_SCAN", "203.0.113.9"))], attacks)
        self.assertEqual(out["finding_precision"], 1.0)

    def test_many_findings_in_one_window_is_still_one_window_caught(self):
        attacks = [R.Attack("scan", 100, 200, set(), set()),
                   R.Attack("dos", 300, 400, set(), set())]
        findings = [(150, self.Fake("PORT_SCAN", "192.0.2.1")) for _ in range(9)]
        out = R.score(findings, attacks)
        self.assertEqual(out["windows_caught"], 1)
        self.assertEqual(out["window_recall"], 0.5)
        self.assertEqual(out["finding_precision"], 1.0)

    def test_an_unasked_scoring_run_reports_none_not_zero(self):
        out = R.score([], [R.Attack("scan", 100, 200, set(), set())])
        self.assertIsNone(out["finding_precision"])
        self.assertEqual(out["window_recall"], 0.0)

    def test_per_label_rolls_up_windows_sharing_a_name(self):
        attacks = [R.Attack("dos", 100, 200, set(), set()),
                   R.Attack("dos", 300, 400, set(), set())]
        out = R.score([(150, self.Fake("X", "192.0.2.1"))], attacks)
        self.assertEqual(out["per_label"]["dos"],
                         {"windows": 2, "caught": 1, "findings": 1,
                          "window_recall": 0.5})


class SafetyTests(unittest.TestCase):
    def test_replay_opens_a_file_and_never_a_socket(self):
        source = (ROOT / "tools" / "replay_pcap.py").read_text()
        for forbidden in ("sniff(", "socket.socket", "sendp(", "send(",
                          "srp(", "urlopen"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
