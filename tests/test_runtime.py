import os
import unittest

from nemos.behavioral import AdaptiveBehaviorProfiler, BehaviorObservation
from nemos.detector import DetectionConfig, ThreatDetector
from nemos.models import TrafficEvent


class RuntimeRegressionTests(unittest.TestCase):
    def test_detection_config_from_env_with_slots_dataclass(self):
        old = os.environ.get("NEMOS_BEHAVIOR_ALPHA")
        try:
            os.environ["NEMOS_BEHAVIOR_ALPHA"] = "0.25"
            cfg = DetectionConfig.from_env()
            self.assertAlmostEqual(cfg.baseline_alpha, 0.25)
        finally:
            if old is None:
                os.environ.pop("NEMOS_BEHAVIOR_ALPHA", None)
            else:
                os.environ["NEMOS_BEHAVIOR_ALPHA"] = old

    def test_non_finite_behavior_env_uses_default(self):
        old = os.environ.get("NEMOS_BEHAVIOR_ALPHA")
        try:
            os.environ["NEMOS_BEHAVIOR_ALPHA"] = "nan"
            self.assertEqual(DetectionConfig.from_env().baseline_alpha, DetectionConfig().baseline_alpha)
        finally:
            if old is None:
                os.environ.pop("NEMOS_BEHAVIOR_ALPHA", None)
            else:
                os.environ["NEMOS_BEHAVIOR_ALPHA"] = old

    def test_behavior_evidence_uses_pre_update_baseline(self):
        profiler = AdaptiveBehaviorProfiler(alpha=0.5, min_samples=2, sample_interval=0, sigma_threshold=1)
        obs = BehaviorObservation(rate=1, bytes_rate=10, unique_destinations=1, unique_ports=1)
        profiler.observe("10.0.0.1", 1.0, obs)
        profiler.observe("10.0.0.1", 2.0, obs)
        result = profiler.observe("10.0.0.1", 3.0, BehaviorObservation(10, 100, 10, 10))
        self.assertIsNotNone(result)
        self.assertEqual(result.baseline["samples"], 2)
        self.assertEqual(result.baseline["rate"], 1.0)

    def test_detector_cooldown_state_is_bounded(self):
        detector = ThreatDetector(DetectionConfig(max_sources=2, cooldown=0))
        for i in range(2000):
            source = f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}"
            detector.process(TrafficEvent("x", source, "10.0.0.1", "TCP", None, 80, 60, "A"))
        self.assertLessEqual(len(detector.events), 2)
        self.assertLessEqual(len(detector.incidents), 2)
        self.assertLessEqual(len(detector.last), 32)


if __name__ == "__main__":
    unittest.main()
