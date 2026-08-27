import unittest

from nemos.behavioral import AdaptiveBehaviorProfiler, BehaviorObservation


class BehavioralProfilerTests(unittest.TestCase):
    def test_warmup_is_not_anomaly(self):
        p = AdaptiveBehaviorProfiler(alpha=0.2, min_samples=3, sample_interval=0, sigma_threshold=2, max_sources=2)
        obs = BehaviorObservation(1.0, 100.0, 1, 1)
        results = [p.observe("10.0.0.1", float(i), obs) for i in range(3)]
        self.assertTrue(all(r is not None and not r.ready for r in results))

    def test_large_multifeature_deviation_is_explainable(self):
        p = AdaptiveBehaviorProfiler(alpha=0.1, min_samples=3, sample_interval=0, sigma_threshold=1.5, max_sources=2)
        for i in range(3):
            p.observe("10.0.0.2", float(i), BehaviorObservation(1.0, 100.0, 1, 1))
        result = p.observe("10.0.0.2", 4.0, BehaviorObservation(20.0, 5000.0, 20, 20))
        self.assertIsNotNone(result)
        self.assertTrue(result.ready)
        self.assertIn("rate", result.deviations)
        self.assertIn("bytes_rate", result.baseline)
        self.assertGreaterEqual(result.confidence, 50)

    def test_profiles_are_bounded(self):
        p = AdaptiveBehaviorProfiler(max_sources=2)
        for i in range(10):
            p.observe(f"10.0.0.{i+1}", float(i), BehaviorObservation(1, 10, 1, 1))
        self.assertEqual(p.size, 2)

if __name__ == "__main__":
    unittest.main()
