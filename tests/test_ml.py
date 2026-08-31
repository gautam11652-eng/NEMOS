from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from nemos.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FeatureVector, extract
from nemos.flows import FlowTable
from nemos.ml import (
    BAND_NORMAL,
    BAND_SUSPICIOUS,
    MIN_TRAINING_SAMPLES,
    AnomalyEngine,
    InsufficientTrainingData,
    classify,
    sklearn_available,
)
from nemos.models import TrafficEvent

HAS_SKLEARN = sklearn_available()
requires_sklearn = unittest.skipUnless(HAS_SKLEARN, "scikit-learn is not installed")


def event(src="192.0.2.10", dst="198.51.100.10", sport=40000, dport=443,
          proto="TCP", size=800, flags="PA"):
    return TrafficEvent("2026-01-01T00:00:00+00:00", src, dst, proto, sport, dport, size, flags)


def normal_vector(source="192.0.2.10", seed=0):
    """A window of ordinary traffic.

    Genuinely randomised rather than cycled: a corpus of near-identical windows
    gives the forest nothing to learn, and training now refuses it outright.
    """
    rng = random.Random(seed)
    table = FlowTable(idle_timeout=1e9)
    for _ in range(rng.randint(18, 60)):
        dport = rng.choice([443, 443, 443, 80, 22, 53])
        proto = "DNS" if dport == 53 else "TCP"
        table.observe(
            event(src=source,
                  dst=f"198.51.100.{rng.choice([10, 11, 12, 20])}",
                  sport=rng.randint(30000, 60000),
                  dport=dport, proto=proto,
                  size=rng.randint(200, 1400),
                  flags="" if proto == "DNS" else rng.choice(["PA", "A", "PA"])),
            now=rng.uniform(0.0, 10.0),
        )
    return extract(source, table.snapshot(), 10.0)


def scan_vector(source="192.0.2.99"):
    """A window of vertical port scanning."""
    table = FlowTable(idle_timeout=1e9)
    for port in range(1, 200):
        table.observe(event(src=source, dst="198.51.100.50", dport=port, size=60, flags="S"),
                      now=float(port) * 0.01)
    return extract(source, table.snapshot(), 10.0)


def corpus(n=120):
    return [normal_vector(f"192.0.2.{10 + (i % 20)}", seed=i) for i in range(n)]


class ClassificationTests(unittest.TestCase):
    def test_bands_are_ordered_and_cover_the_range(self):
        self.assertEqual(classify(0), "NORMAL")
        self.assertEqual(classify(BAND_NORMAL - 1), "NORMAL")
        self.assertEqual(classify(BAND_NORMAL), "SUSPICIOUS")
        self.assertEqual(classify(BAND_SUSPICIOUS), "ANOMALOUS")
        self.assertEqual(classify(100), "HIGHLY_ANOMALOUS")


class TailScoreTests(unittest.TestCase):
    """The score mapping is pure arithmetic and testable without a model.

    Anchors are q50 and q05, so one deviation unit is (q50 - q05). With the
    0..100 ramp below, q50 = 50, q05 = 5 and one unit = 45.
    """

    quantiles = [float(q) for q in range(101)]  # ascending 0..100
    UNIT = 45.0

    def score(self, raw):
        return AnomalyEngine._tail_score(raw, self.quantiles)

    def at(self, deviation):
        """The raw value sitting `deviation` robust units below the median."""
        return self.score(50.0 - deviation * self.UNIT)

    def test_at_or_above_median_is_zero(self):
        self.assertEqual(self.score(50.0), 0)
        self.assertEqual(self.score(90.0), 0)

    def test_within_one_unit_is_zero(self):
        # The 5th percentile of training is unremarkable by construction.
        self.assertEqual(self.at(0.5), 0)
        self.assertEqual(self.at(1.0), 0)

    def test_bulk_of_training_scores_below_the_normal_band(self):
        # A plain percentile rank would put the median at 50; this must not.
        self.assertLess(self.score(50.0), BAND_NORMAL)
        self.assertLess(self.at(1.7), BAND_NORMAL)  # measured normal worst case

    def test_two_units_reaches_the_suspicious_band(self):
        self.assertGreaterEqual(self.at(2.0), BAND_NORMAL)
        self.assertLess(self.at(2.0), BAND_SUSPICIOUS)

    def test_measured_attack_separation_reaches_anomalous(self):
        """Every synthetic attack scenario measured 2.58 units or deeper."""
        for deviation in (2.58, 2.85, 3.26):
            self.assertGreaterEqual(self.at(deviation), BAND_SUSPICIOUS, deviation)

    def test_a_single_training_outlier_cannot_set_the_scale(self):
        """The old mapping anchored on the minimum; one outlier rescaled everything.

        Pushing the training minimum far out must not change how a window two
        deviation units below the median is graded.
        """
        stretched = list(self.quantiles)
        stretched[0] = -10_000.0
        self.assertEqual(
            AnomalyEngine._tail_score(50.0 - 2.6 * self.UNIT, stretched),
            AnomalyEngine._tail_score(50.0 - 2.6 * self.UNIT, self.quantiles),
        )

    def test_score_is_monotonic_and_bounded(self):
        previous = -1
        for raw in range(120, -400, -5):
            score = self.score(float(raw))
            self.assertGreaterEqual(score, previous)
            self.assertTrue(0 <= score <= 100)
            previous = score

    def test_empty_calibration_is_safe(self):
        self.assertEqual(AnomalyEngine._tail_score(1.0, []), 0)

    def test_degenerate_calibration_does_not_divide_by_zero(self):
        flat = [7.0] * 101
        self.assertEqual(AnomalyEngine._tail_score(7.0, flat), 0)
        self.assertEqual(AnomalyEngine._tail_score(1.0, flat), 0)


class UnavailableEngineTests(unittest.TestCase):
    """Every failure mode must degrade, never raise."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)

    def test_missing_model_is_not_an_error(self):
        engine = AnomalyEngine(self.dir)
        self.assertFalse(engine.load())
        self.assertFalse(engine.ready)
        self.assertIn("no trained model", engine.status()["reason"])

    def test_scoring_without_a_model_returns_empty(self):
        engine = AnomalyEngine(self.dir)
        engine.load()
        self.assertEqual(engine.score([normal_vector()]), [])

    def test_scoring_empty_input_returns_empty(self):
        self.assertEqual(AnomalyEngine(self.dir).score([]), [])

    def test_corrupt_model_file_is_handled(self):
        (self.dir).mkdir(parents=True, exist_ok=True)
        engine = AnomalyEngine(self.dir)
        engine.model_path.write_bytes(b"this is not a joblib file")
        engine.metadata_path.write_text(json.dumps({
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": list(FEATURE_NAMES),
            "quantiles": [0.0] * 101,
        }))
        self.assertFalse(engine.load())
        self.assertFalse(engine.ready)

    def test_missing_metadata_is_handled(self):
        (self.dir).mkdir(parents=True, exist_ok=True)
        engine = AnomalyEngine(self.dir)
        engine.model_path.write_bytes(b"x")
        self.assertFalse(engine.load())
        self.assertIn("metadata", engine.status()["reason"])

    def test_unreadable_metadata_is_handled(self):
        (self.dir).mkdir(parents=True, exist_ok=True)
        engine = AnomalyEngine(self.dir)
        engine.model_path.write_bytes(b"x")
        engine.metadata_path.write_text("{not json")
        self.assertFalse(engine.load())

    def test_schema_mismatch_is_refused(self):
        """Scoring a vector the model was not fitted on must never happen."""
        (self.dir).mkdir(parents=True, exist_ok=True)
        engine = AnomalyEngine(self.dir)
        engine.model_path.write_bytes(b"x")
        engine.metadata_path.write_text(json.dumps({
            "feature_schema_version": FEATURE_SCHEMA_VERSION + 99,
            "feature_names": list(FEATURE_NAMES),
            "quantiles": [0.0] * 101,
        }))
        self.assertFalse(engine.load())
        self.assertIn("schema", engine.status()["reason"])

    def test_feature_name_mismatch_is_refused(self):
        (self.dir).mkdir(parents=True, exist_ok=True)
        engine = AnomalyEngine(self.dir)
        engine.model_path.write_bytes(b"x")
        engine.metadata_path.write_text(json.dumps({
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": ["totally", "different"],
            "quantiles": [0.0] * 101,
        }))
        self.assertFalse(engine.load())
        self.assertIn("feature names", engine.status()["reason"])

    def test_status_is_serializable_when_unavailable(self):
        json.dumps(AnomalyEngine(self.dir).status())


@requires_sklearn
class TrainingTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)

    def test_insufficient_data_is_refused(self):
        engine = AnomalyEngine(self.dir)
        with self.assertRaises(InsufficientTrainingData):
            engine.train(corpus(MIN_TRAINING_SAMPLES - 1))

    def test_degenerate_corpus_is_refused(self):
        """Many copies of one window satisfy the row count but teach nothing.

        A forest fitted on a degenerate cloud scores genuinely unusual traffic
        as normal, so this must fail loudly rather than produce a bad model.
        """
        engine = AnomalyEngine(self.dir)
        identical = [normal_vector("192.0.2.10", seed=1) for _ in range(500)]
        with self.assertRaises(InsufficientTrainingData) as ctx:
            engine.train(identical)
        self.assertIn("distinct", str(ctx.exception))
        self.assertFalse(engine.model_path.exists())

    def test_just_enough_distinct_samples_is_accepted(self):
        engine = AnomalyEngine(self.dir)
        varied = [normal_vector(f"192.0.2.{i}", seed=i) for i in range(MIN_TRAINING_SAMPLES + 10)]
        engine.train(varied)
        self.assertTrue(engine.model_path.is_file())

    def test_training_writes_model_and_metadata(self):
        engine = AnomalyEngine(self.dir)
        report = engine.train(corpus())
        self.assertTrue(engine.model_path.is_file())
        self.assertTrue(engine.metadata_path.is_file())
        self.assertEqual(report.features, len(FEATURE_NAMES))
        self.assertEqual(report.schema_version, FEATURE_SCHEMA_VERSION)

    def test_mismatched_schema_in_training_data_is_refused(self):
        engine = AnomalyEngine(self.dir)
        bad = [FeatureVector("x", 10.0, tuple(0.0 for _ in FEATURE_NAMES), schema_version=99)]
        with self.assertRaises(ValueError):
            engine.train(corpus() + bad)

    def test_model_reloads_from_disk(self):
        AnomalyEngine(self.dir).train(corpus())
        reloaded = AnomalyEngine(self.dir)
        self.assertTrue(reloaded.load())
        self.assertTrue(reloaded.ready)

    def test_training_is_reproducible(self):
        """A fixed seed must give identical scores, or results cannot be reproduced."""
        data = corpus()
        probe = [scan_vector()]

        first_dir = self.dir / "a"
        second_dir = self.dir / "b"
        a, b = AnomalyEngine(first_dir), AnomalyEngine(second_dir)
        a.train(data)
        b.train(data)
        self.assertEqual(a.score(probe)[0].raw_score, b.score(probe)[0].raw_score)

    def test_metadata_records_provenance(self):
        AnomalyEngine(self.dir).train(corpus())
        metadata = json.loads((self.dir / "anomaly_model.json").read_text())
        for key in ("feature_schema_version", "feature_names", "samples",
                    "trained_at", "sklearn_version", "quantiles", "random_state"):
            self.assertIn(key, metadata)
        self.assertEqual(len(metadata["quantiles"]), 101)

    def test_atomic_write_leaves_no_temp_files(self):
        AnomalyEngine(self.dir).train(corpus())
        self.assertEqual(list(self.dir.glob("*.tmp")), [])


@requires_sklearn
class InferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.td.name)
        cls.engine = AnomalyEngine(cls.dir)
        cls.engine.train(corpus(200))

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def test_normal_traffic_scores_low(self):
        scores = [r.anomaly_score for r in self.engine.score(corpus(30))]
        median = sorted(scores)[len(scores) // 2]
        self.assertLess(median, BAND_NORMAL, f"normal traffic median was {median}")

    def test_scan_scores_high(self):
        result = self.engine.score([scan_vector()])[0]
        self.assertGreaterEqual(result.anomaly_score, BAND_SUSPICIOUS)
        self.assertIn(result.band, ("ANOMALOUS", "HIGHLY_ANOMALOUS"))

    def test_scan_scores_higher_than_normal(self):
        normal = self.engine.score([normal_vector()])[0].anomaly_score
        scan = self.engine.score([scan_vector()])[0].anomaly_score
        self.assertGreater(scan, normal)

    def test_batch_scoring_preserves_order_and_source(self):
        vectors = [normal_vector("192.0.2.1"), scan_vector("192.0.2.2"), normal_vector("192.0.2.3")]
        results = self.engine.score(vectors)
        self.assertEqual([r.source for r in results], ["192.0.2.1", "192.0.2.2", "192.0.2.3"])

    def test_result_explains_itself(self):
        data = self.engine.score([scan_vector()])[0].as_dict()
        self.assertIn("score_meaning", data)
        self.assertNotIn("probability", data["score_meaning"].lower().split("not a ")[0])
        self.assertTrue(data["contributing_features"])
        for item in data["contributing_features"]:
            self.assertIn(item["feature"], FEATURE_NAMES)

    def test_contributing_features_identify_the_scan_shape(self):
        result = self.engine.score([scan_vector()])[0]
        names = {name for name, _ in result.contributing_features}
        # A vertical scan must surface port diversity as unusual.
        self.assertTrue(
            names & {"destination_port_entropy", "unique_destination_ports", "syn_ratio"},
            f"expected a scan-shaped feature, got {names}",
        )

    def test_mismatched_vector_is_dropped_not_scored(self):
        bad = FeatureVector("x", 10.0, tuple(0.0 for _ in FEATURE_NAMES), schema_version=99)
        self.assertEqual(self.engine.score([bad]), [])

    def test_result_is_json_serializable(self):
        json.dumps([r.as_dict() for r in self.engine.score([normal_vector(), scan_vector()])])

    def test_status_reports_availability(self):
        status = self.engine.status()
        self.assertTrue(status["available"])
        self.assertIsNone(status["reason"])
        self.assertIn("bands", status)


class GracefulDegradationTests(unittest.TestCase):
    def test_engine_constructs_without_sklearn_installed(self):
        # Construction and status must work regardless; only scoring needs the library.
        with tempfile.TemporaryDirectory() as td:
            engine = AnomalyEngine(td)
            self.assertFalse(engine.ready)
            self.assertIsInstance(engine.status(), dict)


if __name__ == "__main__":
    unittest.main()


@requires_sklearn
class WindowContractTests(unittest.TestCase):
    """The aggregation window is part of the feature contract.

    Counts and rates scale with the window, so a model fitted on 10s windows
    describes a different distribution from one applied to 2s windows. Scoring
    across that mismatch produces confident numbers about a distribution the
    model never saw.
    """

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)

    def _corpus(self, window, n=80):
        return [
            FeatureVector(f"192.0.2.{i}", window, normal_vector(f"192.0.2.{i}", seed=i).values)
            for i in range(n)
        ]

    def test_training_records_the_window(self):
        AnomalyEngine(self.dir).train(self._corpus(10.0))
        metadata = json.loads((self.dir / "anomaly_model.json").read_text())
        self.assertEqual(metadata["window_seconds"], 10.0)

    def test_mixed_training_windows_are_refused(self):
        mixed = self._corpus(10.0, 60) + self._corpus(2.0, 60)
        with self.assertRaises(ValueError) as ctx:
            AnomalyEngine(self.dir).train(mixed)
        self.assertIn("window", str(ctx.exception))

    def test_matching_window_loads(self):
        AnomalyEngine(self.dir).train(self._corpus(10.0))
        self.assertTrue(AnomalyEngine(self.dir, window_seconds=10.0).load())

    def test_mismatched_window_is_refused_with_an_actionable_message(self):
        AnomalyEngine(self.dir).train(self._corpus(10.0))
        engine = AnomalyEngine(self.dir, window_seconds=2.0)
        self.assertFalse(engine.load())
        reason = engine.status()["reason"]
        self.assertIn("10.0s windows", reason)
        self.assertIn("2.0s windows", reason)
        # The message must tell the operator how to fix it, both ways.
        self.assertIn("NEMOS_ANALYSIS_WINDOW", reason)
        self.assertIn("--window", reason)

    def test_unspecified_window_skips_the_check(self):
        """A tool inspecting a model need not commit to a runtime window."""
        AnomalyEngine(self.dir).train(self._corpus(10.0))
        self.assertTrue(AnomalyEngine(self.dir).load())
