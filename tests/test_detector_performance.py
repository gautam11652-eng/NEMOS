"""Guards on detection cost.

Detection runs inline on the capture thread, so per-packet cost is dropped
traffic rather than a slow dashboard. When the rule set grew from 10 rules to
27, each rule scanned the window itself: 26 traversals per packet, measured at
853us/packet against 130us before, on a 50-source workload where buckets fill.

The fix was to derive every windowed statistic in one traversal. This asserts
the structural property rather than a wall-clock number, so it cannot flake on
a loaded CI runner but still fails the moment a new rule reintroduces a scan.
"""

import unittest
from collections import deque

from nemos.detector import DetectionConfig, ThreatDetector
from nemos.models import TrafficEvent


class CountingDeque(deque):
    """A deque that records how many times it is iterated."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


class SinglePassTests(unittest.TestCase):
    def _instrumented(self, cfg=None):
        detector = ThreatDetector(cfg or DetectionConfig())
        original = detector._bucket

        def bucket(source):
            existing = detector.events.get(source)
            if existing is None:
                created = CountingDeque(maxlen=detector.cfg.max_events)
                detector.events[source] = created
                return created
            return original(source)

        detector._bucket = bucket
        return detector

    def test_window_is_traversed_once_per_packet(self):
        detector = self._instrumented()
        for i in range(60):
            detector.process(
                TrafficEvent("t", "10.0.0.5", f"10.0.0.{i % 12 + 10}", "TCP",
                             40000, 443, 500, "S"),
                "TCP", now=1000.0 + i * 0.01)
        bucket = detector.events["10.0.0.5"]
        self.assertLessEqual(
            bucket.iterations, 60,
            f"window traversed {bucket.iterations} times for 60 packets; "
            "a rule is scanning the bucket instead of using the aggregate")

    def test_cost_does_not_grow_with_the_number_of_rules_that_fire(self):
        """Traffic that trips many rules must not cost many extra passes."""
        detector = self._instrumented(DetectionConfig(service_dos=20, brute_force=10))
        for i in range(80):
            detector.process(
                TrafficEvent("t", "10.0.0.5", "10.0.0.9", "TCP", 40000, 22, 900, "S"),
                "TCP", now=1000.0 + i * 0.01)
        bucket = detector.events["10.0.0.5"]
        self.assertLessEqual(bucket.iterations, 80)


class MemoisationTests(unittest.TestCase):
    def test_address_validity_is_memoised(self):
        ThreatDetector._ip.cache_clear()
        for _ in range(500):
            ThreatDetector._ip("10.0.0.5")
        info = ThreatDetector._ip.cache_info()
        self.assertEqual(info.misses, 1)
        self.assertEqual(info.hits, 499)

    def test_address_cache_is_bounded(self):
        self.assertIsNotNone(ThreatDetector._ip.cache_info().maxsize)

    def test_internal_classification_cache_is_bounded(self):
        detector = ThreatDetector()
        for i in range(20000):
            detector._private(f"10.{i % 250}.{i % 250}.{i % 250}")
        self.assertLessEqual(len(detector._private_cache), 8192)

    def test_flag_classification_is_cached_and_correct(self):
        from nemos.detector import _flag_class
        self.assertEqual(_flag_class(""), "null")
        self.assertEqual(_flag_class("F"), "fin")
        self.assertEqual(_flag_class("FPU"), "xmas")
        self.assertIsNone(_flag_class("S"))
        self.assertIsNone(_flag_class("PA"))
        self.assertIsNone(_flag_class("SA"))
        self.assertIsNotNone(_flag_class.cache_info().maxsize)


if __name__ == "__main__":
    unittest.main()
