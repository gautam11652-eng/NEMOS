"""Reconnaissance paced below the detection window.

The windowed rules are cheap because the window is short, and that is a
published evasion: spread the same scan over hours and no single window ever
crosses a threshold. These tests drive the scenario the way an attacker
actually would -- one probe at a time, minutes apart -- and assert that the
windowed rules genuinely miss it while the slow tier does not.
"""

from __future__ import annotations

import unittest

from nemos.detector import DetectionConfig, ThreatDetector
from nemos.models import TrafficEvent
from nemos.slowscan import BENIGN_SWEEP_PORTS, SlowHorizonTracker


def tracker(**kwargs) -> SlowHorizonTracker:
    settings = {"horizon": 3600.0, "scan_ports": 40, "sweep_hosts": 30,
                "eval_interval": 30.0, "max_sources": 64, "max_tracked": 256}
    settings.update(kwargs)
    return SlowHorizonTracker(**settings)


def threats(findings) -> set[str]:
    return {finding["threat"] for finding in findings}


class SlowVerticalScan(unittest.TestCase):
    def test_a_scan_paced_one_port_a_minute_is_caught(self):
        slow = tracker()
        now = 0.0
        found: list[dict] = []
        for index in range(60):
            now += 60.0
            slow.observe("203.0.113.9", "192.168.1.10", 1000 + index, now)
            found.extend(slow.evaluate("203.0.113.9", now))
        self.assertIn("SLOW_PORT_SCAN", threats(found))

    def test_evidence_names_the_target_and_the_span(self):
        slow = tracker()
        now = 0.0
        found: list[dict] = []
        for index in range(60):
            now += 60.0
            slow.observe("203.0.113.9", "192.168.1.10", 1000 + index, now)
            found.extend(slow.evaluate("203.0.113.9", now))
        evidence = next(f for f in found if f["threat"] == "SLOW_PORT_SCAN")["evidence"]
        self.assertEqual(evidence["target"], "192.168.1.10")
        self.assertGreaterEqual(evidence["distinct_ports"], 40)
        self.assertEqual(evidence["horizon_seconds"], 3600)

    def test_a_few_ports_is_not_a_scan(self):
        slow = tracker()
        now = 0.0
        found: list[dict] = []
        for port in (22, 80, 443, 3306):
            now += 300.0
            slow.observe("192.168.1.50", "192.168.1.10", port, now)
            found.extend(slow.evaluate("192.168.1.50", now))
        self.assertEqual(found, [])

    def test_ports_spread_across_many_hosts_is_not_a_vertical_scan(self):
        # One port each on 60 hosts is a different shape from 60 ports on one
        # host, and must not trip the vertical rule.
        slow = tracker(sweep_hosts=10_000)
        now = 0.0
        found: list[dict] = []
        for index in range(60):
            now += 60.0
            slow.observe("192.168.1.50", f"10.0.0.{index}", 443, now)
            found.extend(slow.evaluate("192.168.1.50", now))
        self.assertNotIn("SLOW_PORT_SCAN", threats(found))

    def test_activity_older_than_the_horizon_stops_counting(self):
        slow = tracker(horizon=600.0)
        now = 0.0
        for index in range(60):
            now += 5.0
            slow.observe("203.0.113.9", "192.168.1.10", 1000 + index, now)
        # Long after the horizon, the evidence has aged out entirely.
        now += 5000.0
        slow.observe("203.0.113.9", "192.168.1.10", 9999, now)
        self.assertEqual(slow.evaluate("203.0.113.9", now), [])


class SlowHorizontalSweep(unittest.TestCase):
    def test_a_slow_sweep_on_an_uncommon_port_is_caught(self):
        slow = tracker()
        now = 0.0
        found: list[dict] = []
        for index in range(40):
            now += 90.0
            slow.observe("192.168.1.50", f"192.168.1.{index}", 3389, now)
            found.extend(slow.evaluate("192.168.1.50", now))
        self.assertIn("SLOW_HOST_SWEEP", threats(found))

    def test_web_browsing_is_not_a_sweep(self):
        """The false positive this rule would otherwise generate constantly.

        A workstation contacts hundreds of hosts an hour on 443. That has the
        same shape as a horizontal sweep and none of the meaning.
        """
        slow = tracker()
        now = 0.0
        found: list[dict] = []
        for index in range(200):
            now += 15.0
            slow.observe("192.168.1.50", f"93.184.216.{index % 256}", 443, now)
            found.extend(slow.evaluate("192.168.1.50", now))
        self.assertNotIn("SLOW_HOST_SWEEP", threats(found))

    def test_dns_to_many_resolvers_is_not_a_sweep(self):
        slow = tracker()
        now = 0.0
        found: list[dict] = []
        for index in range(100):
            now += 30.0
            slow.observe("192.168.1.50", f"10.1.{index // 256}.{index % 256}", 53, now)
            found.extend(slow.evaluate("192.168.1.50", now))
        self.assertNotIn("SLOW_HOST_SWEEP", threats(found))

    def test_the_benign_port_list_covers_the_common_client_protocols(self):
        for port in (53, 80, 443, 123):
            self.assertIn(port, BENIGN_SWEEP_PORTS)


class ReportingDiscipline(unittest.TestCase):
    def test_evaluation_is_rate_limited_per_source(self):
        """The cost control: the bounded walk must not run per packet."""
        slow = tracker(eval_interval=30.0)
        slow.observe("203.0.113.9", "192.168.1.10", 80, 100.0)
        self.assertEqual(slow.evaluate("203.0.113.9", 100.0), [])
        # Second call inside the interval short-circuits before any walk.
        self.assertEqual(slow.evaluate("203.0.113.9", 101.0), [])

    def test_a_finding_is_not_repeated_every_interval(self):
        """At most one report per horizon, not one per evaluation.

        Not "exactly one ever": a scan still running two hours later is
        ongoing activity, and reporting it hourly is right where going
        permanently silent after the first finding would not be. What must
        not happen is a finding every eval_interval, which over two hours
        would be 240 copies of the same thing.
        """
        slow = tracker()
        now = 0.0
        times: list[float] = []
        for index in range(120):
            now += 60.0
            slow.observe("203.0.113.9", "192.168.1.10", 1000 + index, now)
            if slow.evaluate("203.0.113.9", now):
                times.append(now)
        self.assertGreaterEqual(len(times), 1, "the slow scan was never reported")
        self.assertLessEqual(len(times), 2, f"reported {len(times)} times in two hours")
        for earlier, later in zip(times, times[1:], strict=False):
            self.assertGreaterEqual(
                later - earlier, slow.horizon,
                "the same finding repeated inside one horizon")

    def test_a_source_already_caught_by_a_fast_rule_is_not_reported_twice(self):
        slow = tracker()
        now = 0.0
        for index in range(60):
            now += 60.0
            slow.observe("203.0.113.9", "192.168.1.10", 1000 + index, now)
            if index == 0:
                slow.note_fast_finding("203.0.113.9", now)
        self.assertEqual(slow.evaluate("203.0.113.9", now), [])

    def test_an_unknown_source_evaluates_to_nothing(self):
        self.assertEqual(tracker().evaluate("10.0.0.1", 1.0), [])

    def test_a_packet_without_a_port_is_ignored(self):
        slow = tracker()
        slow.observe("10.0.0.1", "10.0.0.2", None, 1.0)
        self.assertEqual(slow.sources.get("10.0.0.1"), None)


class BoundedState(unittest.TestCase):
    def test_the_source_table_is_bounded(self):
        slow = tracker(max_sources=32)
        for index in range(5000):
            slow.observe(f"10.0.{index // 256}.{index % 256}", "192.168.1.1", 80, 1.0)
        self.assertLessEqual(len(slow.sources), 33)

    def test_a_single_source_cannot_grow_without_limit(self):
        slow = tracker(max_tracked=64)
        for port in range(5000):
            slow.observe("203.0.113.9", "192.168.1.10", port, 1.0)
        self.assertLessEqual(len(slow.sources["203.0.113.9"].seen), 64)

    def test_eviction_keeps_the_most_interesting_source_not_the_newest(self):
        """Plain LRU would be exactly backwards here.

        A slow scanner is, by definition, the least recently active thing
        being tracked. Evicting by recency would discard precisely the
        sources this module exists to catch.
        """
        slow = tracker(max_sources=4, horizon=100_000.0)
        # One patient scanner with a lot of distinct evidence, seen early.
        for port in range(50):
            slow.observe("203.0.113.9", "192.168.1.10", 1000 + port, 1.0)
        # Then a stream of newer, uninteresting single-contact sources.
        for index in range(50):
            slow.observe(f"10.0.0.{index}", "192.168.1.1", 443, 100.0 + index)
        self.assertIn("203.0.113.9", slow.sources,
                      "the scanner was evicted in favour of newer noise")

    def test_fully_expired_sources_are_dropped_first(self):
        slow = tracker(max_sources=4, horizon=100.0)
        for index in range(6):
            slow.observe(f"10.0.0.{index}", "192.168.1.1", 443, 1.0)
        slow.observe("203.0.113.9", "192.168.1.10", 80, 10_000.0)
        self.assertIn("203.0.113.9", slow.sources)
        self.assertLessEqual(len(slow.sources), 5)

    def test_metrics_report_the_tracked_size(self):
        slow = tracker()
        slow.observe("10.0.0.1", "10.0.0.2", 80, 1.0)
        self.assertEqual(slow.metrics()["tracked_sources"], 1)
        self.assertEqual(slow.metrics()["horizon_seconds"], 3600)


class ThroughTheDetector(unittest.TestCase):
    """The evasion end to end: windowed rules miss it, the slow tier does not."""

    def scan(self, detector, pace: float, ports: int = 60):
        now = 0.0
        alerts = []
        for index in range(ports):
            now += pace
            event = TrafficEvent(
                "2026-01-01T00:00:00+00:00", "203.0.113.9", "192.168.1.10",
                "TCP", 40000 + index, 1000 + index, 60, "S", "eth0", metadata={},
            )
            alerts.extend(detector.process(event, "TCP", now=now))
        return alerts

    def test_the_windowed_rules_genuinely_miss_a_slow_scan(self):
        """Without this, the slow tier would be solving a problem that isn't there."""
        detector = ThreatDetector(DetectionConfig(
            window=10, port_scan=8, slow_scan_ports=100_000))
        threats_found = {alert.threat for alert in self.scan(detector, pace=60.0)}
        self.assertNotIn("PORT_SCAN", threats_found,
                         "the windowed rule caught it, so this is not an evasion")

    def test_the_slow_tier_catches_what_the_window_misses(self):
        detector = ThreatDetector(DetectionConfig(
            window=10, port_scan=8, slow_scan_ports=40, slow_eval_interval=30.0))
        threats_found = {alert.threat for alert in self.scan(detector, pace=60.0)}
        self.assertIn("SLOW_PORT_SCAN", threats_found)

    def test_a_slow_finding_carries_a_technique_and_evidence(self):
        detector = ThreatDetector(DetectionConfig(
            window=10, port_scan=8, slow_scan_ports=40, slow_eval_interval=30.0))
        alert = next(a for a in self.scan(detector, pace=60.0)
                     if a.threat == "SLOW_PORT_SCAN")
        # An external source scanning is reconnaissance, not internal discovery.
        self.assertEqual(alert.technique, "T1595")
        self.assertEqual(alert.evidence["target"], "192.168.1.10")

    def test_a_fast_scan_is_not_also_reported_as_a_slow_one(self):
        detector = ThreatDetector(DetectionConfig(
            window=10, port_scan=8, slow_scan_ports=40, slow_eval_interval=1.0))
        found = [alert.threat for alert in self.scan(detector, pace=0.05)]
        self.assertIn("PORT_SCAN", found)
        self.assertNotIn("SLOW_PORT_SCAN", found,
                         "one behaviour was reported by both tiers")


if __name__ == "__main__":
    unittest.main()
