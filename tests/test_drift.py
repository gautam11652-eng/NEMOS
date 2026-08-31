"""Model staleness and drift.

An Isolation Forest learns one network at one point in time, and NEMOS trains
it by hand and then never mentions it again. Both failure modes are silent:
traffic moves away from the training distribution and ordinary work starts
scoring anomalous, or the network grows into what the model considers normal
and it stops flagging things it should. In each case the dashboard shows a
model that is loaded and scoring, which is what it shows when all is well.

These tests pin the three signals and, just as importantly, the cases where
the monitor must stay quiet -- a drift warning that fires on healthy traffic
would be trained away by the operator within a week.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from nemos.drift import (
    DRIFT_SIGMA,
    MIN_SAMPLES_FOR_DRIFT,
    STALE_AFTER_DAYS,
    DriftMonitor,
)

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def metadata(trained_days_ago: float = 1.0, features: int = 4,
             mean: float = 10.0, std: float = 2.0) -> dict:
    return {
        "trained_at": (NOW - timedelta(days=trained_days_ago)).isoformat(timespec="seconds"),
        "samples": 5000,
        "feature_names": [f"feature_{i}" for i in range(features)],
        "feature_mean": [mean] * features,
        "feature_std": [std] * features,
    }


def feed(monitor: DriftMonitor, values: list[float], count: int, score: int = 5) -> None:
    for _ in range(count):
        monitor.observe(values, score)


class Staleness(unittest.TestCase):
    def test_a_fresh_model_is_not_stale(self):
        report = DriftMonitor().assess(metadata(trained_days_ago=3), NOW)
        self.assertFalse(report["stale"])
        self.assertAlmostEqual(report["age_days"], 3.0, places=1)

    def test_an_old_model_is_reported_stale(self):
        report = DriftMonitor().assess(metadata(trained_days_ago=STALE_AFTER_DAYS + 10), NOW)
        self.assertTrue(report["stale"])
        self.assertTrue(any("retrain" in reason for reason in report["reasons"]))

    def test_age_is_reported_even_without_a_verdict(self):
        report = DriftMonitor().assess(metadata(trained_days_ago=45), NOW)
        self.assertFalse(report["stale"])
        self.assertAlmostEqual(report["age_days"], 45.0, places=1)

    def test_missing_or_malformed_training_time_is_not_an_error(self):
        for value in (None, "", "not-a-timestamp", 12345):
            with self.subTest(value=value):
                report = DriftMonitor().assess({"trained_at": value}, NOW)
                self.assertIsNone(report["age_days"])
                self.assertFalse(report["stale"])

    def test_a_naive_timestamp_is_treated_as_utc_rather_than_crashing(self):
        report = DriftMonitor().assess({"trained_at": "2026-01-01T00:00:00"}, NOW)
        self.assertIsNotNone(report["age_days"])


class NotEnoughEvidence(unittest.TestCase):
    def test_drift_is_not_judged_before_enough_windows(self):
        monitor = DriftMonitor()
        feed(monitor, [1000.0, 1000.0, 1000.0, 1000.0], MIN_SAMPLES_FOR_DRIFT - 1)
        report = monitor.assess(metadata(), NOW)
        self.assertFalse(report["drifted"],
                         "a verdict was reached on too little data")

    def test_the_absence_of_a_verdict_is_stated_not_implied(self):
        report = DriftMonitor().assess(metadata(), NOW)
        self.assertTrue(any("not assessed" in reason for reason in report["reasons"]))

    def test_the_window_count_is_always_reported(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, 25)
        self.assertEqual(monitor.assess(metadata(), NOW)["scored_windows"], 25)


class FeatureDrift(unittest.TestCase):
    def test_traffic_matching_training_does_not_drift(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0, 10.0, 10.0, 10.0], MIN_SAMPLES_FOR_DRIFT + 50)
        report = monitor.assess(metadata(mean=10.0, std=2.0), NOW)
        self.assertFalse(report["drifted"])
        self.assertEqual(report["drifted_features"], [])

    def test_a_moved_distribution_is_detected(self):
        monitor = DriftMonitor()
        # 10 training sigmas away on every feature.
        feed(monitor, [30.0, 30.0, 30.0, 30.0], MIN_SAMPLES_FOR_DRIFT + 50)
        report = monitor.assess(metadata(mean=10.0, std=2.0), NOW)
        self.assertTrue(report["drifted"])
        self.assertEqual(len(report["drifted_features"]), 4)

    def test_the_report_names_the_features_and_their_distance(self):
        monitor = DriftMonitor()
        feed(monitor, [30.0, 30.0, 30.0, 30.0], MIN_SAMPLES_FOR_DRIFT + 50)
        drifted = monitor.assess(metadata(mean=10.0, std=2.0), NOW)["drifted_features"][0]
        self.assertEqual(drifted["feature"], "feature_0")
        self.assertAlmostEqual(drifted["training_mean"], 10.0)
        self.assertAlmostEqual(drifted["observed_mean"], 30.0)
        self.assertAlmostEqual(drifted["sigma"], 10.0, places=1)

    def test_one_moved_feature_is_a_changed_service_not_a_changed_network(self):
        monitor = DriftMonitor()
        feed(monitor, [30.0, 10.0, 10.0, 10.0], MIN_SAMPLES_FOR_DRIFT + 50)
        report = monitor.assess(metadata(mean=10.0, std=2.0), NOW)
        self.assertFalse(report["drifted"], "a single moved feature raised a verdict")
        self.assertEqual(len(report["drifted_features"]), 1,
                         "the moved feature should still be reported as evidence")

    def test_a_deviation_just_below_the_threshold_does_not_count(self):
        monitor = DriftMonitor()
        value = 10.0 + (DRIFT_SIGMA - 0.5) * 2.0
        feed(monitor, [value] * 4, MIN_SAMPLES_FOR_DRIFT + 50)
        self.assertFalse(monitor.assess(metadata(mean=10.0, std=2.0), NOW)["drifted"])

    def test_a_zero_variance_feature_is_skipped_not_divided_by(self):
        """Dividing by a zero training spread would manufacture infinite drift."""
        monitor = DriftMonitor()
        feed(monitor, [50.0, 10.0, 10.0, 10.0], MIN_SAMPLES_FOR_DRIFT + 50)
        meta = metadata(mean=10.0, std=2.0)
        meta["feature_std"] = [0.0, 2.0, 2.0, 2.0]
        report = monitor.assess(meta, NOW)
        self.assertNotIn("feature_0", [d["feature"] for d in report["drifted_features"]])

    def test_a_metadata_width_mismatch_says_so_instead_of_reporting_health(self):
        """A check that cannot run must not look like a check that passed.

        This is how the feature-drift signal was once silently dead: the
        engine passed metadata that did not carry the training mean and
        spread, and traffic dozens of sigmas from training was reported as
        no drift at all -- identical to a healthy model.
        """
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, MIN_SAMPLES_FOR_DRIFT + 50)
        report = monitor.assess(metadata(features=8), NOW)
        self.assertFalse(report["drift_comparable"])
        self.assertTrue(any("could not be assessed" in r for r in report["reasons"]))

    def test_missing_training_statistics_are_reported_not_ignored(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, MIN_SAMPLES_FOR_DRIFT + 50)
        report = monitor.assess({"trained_at": NOW.isoformat()}, NOW)
        self.assertFalse(report["drift_comparable"])

    def test_a_usable_comparison_is_marked_comparable(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, MIN_SAMPLES_FOR_DRIFT + 50)
        self.assertTrue(monitor.assess(metadata(), NOW)["drift_comparable"])

    def test_a_vector_of_the_wrong_width_is_ignored(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, 10)
        monitor.observe([1.0, 2.0], 5)
        self.assertEqual(monitor.assess(metadata(), NOW)["scored_windows"], 10)


class ScoreInflation(unittest.TestCase):
    def test_mostly_normal_scores_are_not_inflated(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, MIN_SAMPLES_FOR_DRIFT + 50, score=5)
        report = monitor.assess(metadata(), NOW)
        self.assertFalse(report["score_inflated"])
        self.assertLess(report["anomalous_fraction"], 0.1)

    def test_most_windows_anomalous_suggests_a_stale_calibration(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, MIN_SAMPLES_FOR_DRIFT + 50, score=85)
        report = monitor.assess(metadata(), NOW)
        self.assertTrue(report["score_inflated"])
        self.assertAlmostEqual(report["anomalous_fraction"], 1.0)

    def test_the_reason_does_not_assert_the_network_is_hostile(self):
        monitor = DriftMonitor()
        feed(monitor, [10.0] * 4, MIN_SAMPLES_FOR_DRIFT + 50, score=85)
        reasons = " ".join(monitor.assess(metadata(), NOW)["reasons"])
        self.assertIn("more", reasons.lower())
        self.assertIn("likely", reasons.lower())


class Resetting(unittest.TestCase):
    def test_reset_clears_the_live_statistics(self):
        monitor = DriftMonitor()
        feed(monitor, [30.0] * 4, MIN_SAMPLES_FOR_DRIFT + 50)
        self.assertTrue(monitor.assess(metadata(mean=10.0, std=2.0), NOW)["drifted"])
        monitor.reset()
        report = monitor.assess(metadata(mean=10.0, std=2.0), NOW)
        self.assertEqual(report["scored_windows"], 0)
        self.assertFalse(report["drifted"])


class RunningStatistics(unittest.TestCase):
    def test_the_mean_is_accumulated_correctly_over_many_windows(self):
        monitor = DriftMonitor()
        for value in range(1, 1001):
            monitor.observe([float(value)], 0)
        # Mean of 1..1000 is 500.5; the model compares against this, so an
        # accumulation error would silently shift every verdict.
        meta = {"feature_mean": [500.5], "feature_std": [1.0],
                "feature_names": ["x"], "trained_at": NOW.isoformat()}
        self.assertEqual(monitor.assess(meta, NOW)["drifted_features"], [])

    def test_accumulation_stays_stable_over_a_long_run(self):
        """Welford's method, not a naive sum, so precision holds up."""
        monitor = DriftMonitor()
        for _ in range(50_000):
            monitor.observe([1_000_000.0], 0)
        meta = {"feature_mean": [1_000_000.0], "feature_std": [1.0],
                "feature_names": ["x"], "trained_at": NOW.isoformat()}
        self.assertEqual(monitor.assess(meta, NOW)["drifted_features"], [])


class ThroughTheEngine(unittest.TestCase):
    """Against a real trained model, not hand-written metadata.

    The unit tests above pass metadata built by hand, which is why they did
    not catch that the engine strips feature_mean and feature_std out of
    _metadata and so was handing the monitor nothing to compare against.
    """

    def setUp(self):
        try:
            import sklearn  # noqa: F401
        except ImportError:
            self.skipTest("scikit-learn is not installed")

    def engine(self, directory):
        from nemos.ml import AnomalyEngine
        return AnomalyEngine(directory, window_seconds=10.0)

    def vectors(self, scale, count, seed=7):
        import random
        from nemos.features import FEATURE_NAMES, FeatureVector
        rng = random.Random(seed)
        return [
            FeatureVector(
                source=f"10.0.0.{index % 50}", window_seconds=10.0,
                values=tuple(abs(rng.gauss(10 * scale, 2)) for _ in FEATURE_NAMES),
            )
            for index in range(count)
        ]

    def test_health_is_reported_in_engine_status(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            health = self.engine(Path(directory)).status()["health"]
            for key in ("stale", "drifted", "reasons", "drift_comparable"):
                self.assertIn(key, health)

    def test_traffic_like_the_training_data_does_not_drift(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            engine = self.engine(Path(directory))
            engine.train(self.vectors(1.0, 600))
            for _ in range(12):
                engine.score(self.vectors(1.0, 20, seed=11))
            health = engine.status()["health"]
            self.assertTrue(health["drift_comparable"])
            self.assertFalse(health["drifted"])

    def test_traffic_far_from_the_training_data_is_reported_as_drift(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            engine = self.engine(Path(directory))
            engine.train(self.vectors(1.0, 600))
            for _ in range(12):
                engine.score(self.vectors(8.0, 20, seed=13))
            health = engine.status()["health"]
            self.assertTrue(health["drift_comparable"],
                            "the engine handed the monitor nothing to compare against")
            self.assertTrue(health["drifted"])
            self.assertGreater(len(health["drifted_features"]), 0)

    def test_training_clears_statistics_from_the_previous_model(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            engine = self.engine(Path(directory))
            engine.train(self.vectors(1.0, 600))
            for _ in range(12):
                engine.score(self.vectors(8.0, 20, seed=13))
            self.assertGreater(engine.status()["health"]["scored_windows"], 0)
            engine.train(self.vectors(8.0, 600, seed=17))
            self.assertEqual(engine.status()["health"]["scored_windows"], 0,
                             "a retrained model inherited the old model's statistics")


if __name__ == "__main__":
    unittest.main()
