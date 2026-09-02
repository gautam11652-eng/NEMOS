"""The ML model has to bootstrap itself, and has to do it safely.

Before this, ML anomaly scoring was inert on every deployment where nobody ran
``tools/train_model.py`` by hand -- which is most of them. The sensor captured,
detected and alerted, and the model slot sat permanently empty while the
console reported "no trained model".

Making it automatic is only an improvement if two things stay true, and both
are easier to break than to get right:

- **The corpus stays clean.** A model that trains on whatever is on the wire
  learns to accept an intrusion in progress. Every window here has to have been
  judged unremarkable by the layers NEMOS already has.
- **A failed retrain costs nothing.** The sensor must keep scoring with the
  model it has while a replacement is fitted, and must still have it if the
  replacement turns out to be unusable.

These tests hold both, plus the states in between.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import scenarios  # noqa: E402

from nemos.analysis import AnalysisEngine  # noqa: E402
from nemos.behavioral import STATE_NO_BASELINE  # noqa: E402
from nemos.bootstrap import (  # noqa: E402
    STATE_ACTIVE,
    STATE_NO_MODEL,
    STATE_WARMING_UP,
    ModelBootstrap,
    is_clean,
)
from nemos.database import connect, initialize  # noqa: E402
from nemos.detector import ThreatDetector  # noqa: E402
from nemos.features import FEATURE_SCHEMA_VERSION, FeatureVector  # noqa: E402
from nemos.fusion import VERDICT_BENIGN, assess  # noqa: E402
from nemos.ml import MIN_TRAINING_SAMPLES, AnomalyEngine, sklearn_available  # noqa: E402

WINDOW = 10.0
needs_sklearn = unittest.skipUnless(
    sklearn_available(), "scikit-learn is not installed; ML training cannot run"
)


class BootstrapHarness(unittest.TestCase):
    """A real AnalysisEngine over a real database and real synthetic traffic.

    Deliberately not a mock: the thing under test is the interaction between
    fusion's verdict, the sample filter and the training engine, and a stubbed
    assessment would assert only that the stub was written correctly.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.db = self.root / "nemos.db"
        initialize(self.db)

    def engine(self, *, autotrain=True, min_samples=60, min_seconds=0.0,
               retrain_seconds=0.0, window=WINDOW, model_dir=None) -> AnalysisEngine:
        engine = AnalysisEngine(
            model_dir=model_dir or (self.root / "model"),
            window_seconds=window,
            db_path=self.db,
            autotrain=autotrain,
            bootstrap_min_seconds=min_seconds,
            bootstrap_min_samples=min_samples,
            retrain_seconds=retrain_seconds,
        )
        self.addCleanup(lambda: engine.bootstrap and engine.bootstrap.stop(timeout=10))
        return engine

    def feed_normal(self, engine: AnalysisEngine, windows: int) -> None:
        """Push ordinary traffic through the engine's real ingress path."""
        now = 0.0
        for scenario in scenarios.training_corpus(windows=windows, window_seconds=WINDOW):
            for _offset, event in scenario.events:
                engine.observe(event)
            now += WINDOW
            engine.run_cycle(now=now, force=True)

    def feed_attack(self, engine: AnalysisEngine, name: str, start: float) -> float:
        """Push one named attack scenario through, with its rule findings."""
        detector = ThreatDetector()
        scenario = scenarios.build(name)
        for _offset, event in scenario.events:
            engine.observe(event)
            alerts = detector.process(event, event.protocol)
            if alerts:
                engine.record_rule_alerts(event.source, alerts)
        engine.run_cycle(now=start + WINDOW, force=True)
        return start + WINDOW

    def corpus_size(self) -> int:
        c = connect(self.db)
        try:
            return int(c.execute("SELECT COUNT(*) FROM ml_training_samples").fetchone()[0])
        finally:
            c.close()

    def corpus_sources(self) -> set[str]:
        c = connect(self.db)
        try:
            return {r["source"] for r in c.execute("SELECT source FROM ml_training_samples")}
        finally:
            c.close()

    def wait_for(self, bootstrap: ModelBootstrap, *states, timeout=90.0) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if bootstrap.state in states:
                return bootstrap.state
            time.sleep(0.05)
        return bootstrap.state


class ColdStart(BootstrapHarness):
    def test_a_sensor_with_no_model_starts_and_reports_warming_up(self):
        """A missing model is a state to report, never a reason to fail."""
        engine = self.engine()
        engine.model.load()
        engine.bootstrap.start()

        self.assertEqual(engine.bootstrap.state, STATE_WARMING_UP)
        self.assertFalse(engine.model.status()["available"])
        self.assertFalse(engine.model.model_path.exists())

        status = engine.status()
        self.assertEqual(status["bootstrap"]["state"], STATE_WARMING_UP)
        self.assertEqual(status["bootstrap"]["samples_required"],
                         status["bootstrap"]["samples_required"])
        self.assertFalse(status["model"]["available"])

    def test_deterministic_detection_runs_with_no_model_at_all(self):
        """The rules layer has never needed the model and still must not."""
        engine = self.engine()
        engine.model.load()
        detector = ThreatDetector()
        found = []
        for _offset, event in scenarios.build("port_sweep").events:
            found.extend(detector.process(event, event.protocol))

        self.assertFalse(engine.model.status()["available"])
        self.assertTrue(found, "port sweep produced no deterministic finding without ML")
        self.assertIn("PORT_SCAN", {a.threat for a in found})

    def test_behavioral_baseline_runs_with_no_model_at_all(self):
        """The statistical layer is independent of the forest and stays so."""
        engine = self.engine()
        engine.model.load()
        self.feed_normal(engine, 20)

        baselines = engine.baselines(limit=50)
        self.assertTrue(baselines, "no baseline was built without a model")
        self.assertTrue(
            any(b["state"] != STATE_NO_BASELINE for b in baselines),
            "every baseline stayed in NO_BASELINE, so the layer did not run",
        )

    def test_disabling_autotrain_collects_nothing_and_says_so(self):
        engine = self.engine(autotrain=False)
        engine.bootstrap.start()
        self.feed_normal(engine, 20)

        self.assertEqual(engine.bootstrap.state, STATE_NO_MODEL)
        self.assertEqual(self.corpus_size(), 0)
        self.assertIn("disabled", engine.bootstrap.status()["reason"])


class TheCorpusIsVetted(BootstrapHarness):
    """What may and may not become training data."""

    def test_ordinary_windows_are_collected(self):
        engine = self.engine(min_samples=100_000)  # never trains; only collects
        self.feed_normal(engine, 30)
        self.assertGreater(self.corpus_size(), 0)
        self.assertEqual(engine.bootstrap.status()["samples_rejected"], 0)

    def test_a_window_a_rule_fired_on_never_enters_the_corpus(self):
        """End to end: a scan must not teach the model that scanning is normal.

        This exercises the vetting as a whole -- the verdict filter and the
        quarantine together -- which is the property that actually matters.
        Each half is pinned separately below and above.
        """
        engine = self.engine(min_samples=100_000)
        self.feed_normal(engine, 5)
        clean_sources = self.corpus_sources()

        attacker_sources = set()
        now = 50.0
        for name in ("port_sweep", "destination_fanout", "icmp_sweep"):
            scenario = scenarios.build(name)
            attacker_sources.update(e.source for _o, e in scenario.events)
            now = self.feed_attack(engine, name, now)

        added = self.corpus_sources() - clean_sources
        self.assertFalse(
            added & attacker_sources,
            f"attack sources reached the training corpus: {sorted(added & attacker_sources)}",
        )

    def test_a_source_stays_out_for_several_windows_after_a_finding(self):
        """A rule firing late in a window is fused into the *next* one, so the
        window it actually fired during would otherwise look clean."""
        engine = self.engine(min_samples=100_000)
        bootstrap = engine.bootstrap
        vector = FeatureVector("198.51.100.9", WINDOW, tuple(1.0 for _ in range(24)))
        benign = assess(vector.source, rule_alerts=[], anomaly=None, baseline=None)
        self.assertEqual(benign.verdict, VERDICT_BENIGN)

        bootstrap.note_rule_finding(vector.source, now=100.0)
        self.assertFalse(bootstrap.observe(vector, benign, now=100.0))
        self.assertFalse(bootstrap.observe(vector, benign, now=100.0 + WINDOW))
        # Quarantine is 3 windows by default; past it the source is eligible again.
        self.assertTrue(bootstrap.observe(vector, benign, now=100.0 + 4 * WINDOW))

    def test_incomplete_and_empty_windows_are_refused(self):
        names = tuple(f"f{i}" for i in range(24))
        del names
        empty = FeatureVector("10.0.0.1", WINDOW, tuple(0.0 for _ in range(24)))
        benign = assess("10.0.0.1", rule_alerts=[], anomaly=None, baseline=None)
        keep, why = is_clean(empty, benign)
        self.assertFalse(keep)
        self.assertIn("empty", why)

        nonfinite = FeatureVector(
            "10.0.0.2", WINDOW, (float("nan"),) + tuple(1.0 for _ in range(23)))
        keep, why = is_clean(nonfinite, benign)
        self.assertFalse(keep)
        self.assertIn("finite", why)

        stale_schema = FeatureVector(
            "10.0.0.3", WINDOW, tuple(1.0 for _ in range(24)),
            schema_version=FEATURE_SCHEMA_VERSION + 1)
        self.assertFalse(is_clean(stale_schema, benign)[0])

    def test_a_flagged_verdict_alone_keeps_a_window_out(self):
        """Isolates the verdict filter from the quarantine beside it.

        The integration test above passes even with this check removed,
        because the quarantine catches the same sources by a different route.
        Both mechanisms are load-bearing -- the quarantine covers the window a
        rule fired *during*, this covers every window fusion flagged for any
        reason, including a purely statistical one no rule saw -- so each
        needs a test that fails when only it is broken.
        """
        vector = FeatureVector("203.0.113.7", WINDOW, tuple(2.0 for _ in range(24)))
        flagged = assess(
            vector.source,
            rule_alerts=[{"threat": "PORT_SCAN", "severity": "HIGH", "risk_score": 80,
                          "confidence": 80, "technique": "T1046", "reason": "scan"}],
            anomaly=None, baseline=None,
        )
        self.assertNotEqual(flagged.verdict, VERDICT_BENIGN)

        keep, why = is_clean(vector, flagged)
        self.assertFalse(keep, "a window NEMOS flagged was accepted as training data")
        self.assertIn(flagged.verdict, why)

        # And through the collector, with no quarantine in play at all.
        bootstrap = self.engine(min_samples=100_000).bootstrap
        self.assertFalse(bootstrap.observe(vector, flagged, now=0.0))
        self.assertEqual(bootstrap.status()["samples_rejected"], 1)

    def test_a_window_with_no_assessment_is_refused(self):
        vector = FeatureVector("10.0.0.4", WINDOW, tuple(1.0 for _ in range(24)))
        self.assertFalse(is_clean(vector, None)[0])


class TrainingTriggers(BootstrapHarness):
    def test_too_few_samples_do_not_start_a_training_run(self):
        engine = self.engine(min_samples=5_000)
        self.feed_normal(engine, 10)
        self.assertEqual(engine.bootstrap.state, STATE_WARMING_UP)
        self.assertEqual(engine.bootstrap.status()["trainings"], 0)
        self.assertFalse(engine.model.model_path.exists())

    def test_the_observation_period_gates_training_on_its_own(self):
        """Sample count alone is satisfied by one quiet minute repeated."""
        engine = self.engine(min_samples=10, min_seconds=86_400.0)
        self.feed_normal(engine, 30)
        self.assertGreaterEqual(self.corpus_size(), 10)
        self.assertEqual(engine.bootstrap.state, STATE_WARMING_UP)
        self.assertEqual(engine.bootstrap.status()["trainings"], 0)

    def test_the_sample_floor_cannot_be_configured_below_what_training_accepts(self):
        """A lower setting would only schedule a run that is always refused."""
        bootstrap = ModelBootstrap(
            engine=AnomalyEngine(self.root / "model", window_seconds=WINDOW),
            db_path=self.db, window_seconds=WINDOW, min_samples=1,
        )
        self.assertEqual(bootstrap.min_samples, MIN_TRAINING_SAMPLES)

    @needs_sklearn
    def test_enough_clean_samples_train_validate_and_activate_a_real_model(self):
        engine = self.engine(min_samples=60)
        engine.model.load()
        engine.bootstrap.start()
        self.feed_normal(engine, 90)

        self.assertEqual(self.wait_for(engine.bootstrap, STATE_ACTIVE), STATE_ACTIVE)

        status = engine.bootstrap.status()
        self.assertEqual(status["trainings"], 1)
        self.assertEqual(status["failures"], 0)
        self.assertTrue(status["auto_trained"])

        # ACTIVE has to mean a real fitted forest, not a flag.
        self.assertTrue(engine.model.model_path.is_file())
        self.assertTrue(engine.model.status()["available"])
        metadata = json.loads(engine.model.metadata_path.read_text())
        self.assertEqual(metadata["feature_schema_version"], FEATURE_SCHEMA_VERSION)
        self.assertEqual(metadata["window_seconds"], WINDOW)
        self.assertGreaterEqual(metadata["samples"], 60)
        self.assertIn("sklearn_version", metadata)

        # And it must actually score.
        results = engine.model.score([
            FeatureVector("10.0.0.9", WINDOW, tuple(float(i) for i in range(24)))
        ])
        self.assertEqual(len(results), 1)
        self.assertTrue(0 <= results[0].anomaly_score <= 100)

    @needs_sklearn
    def test_the_staging_directory_is_cleaned_up_after_a_run(self):
        engine = self.engine(min_samples=60)
        engine.bootstrap.start()
        self.feed_normal(engine, 90)
        self.wait_for(engine.bootstrap, STATE_ACTIVE)
        self.assertFalse((engine.model.model_dir / ".staging").exists())

    @needs_sklearn
    def test_training_does_not_block_the_analysis_cycle(self):
        """Fitting a forest on the analysis thread would stall window expiry,
        and behind it the flow table the capture thread appends to."""
        engine = self.engine(min_samples=60)
        engine.bootstrap.start()
        self.feed_normal(engine, 70)

        # A cycle issued while the worker is fitting must return promptly.
        started = time.monotonic()
        for scenario in scenarios.training_corpus(windows=3, window_seconds=WINDOW):
            for _offset, event in scenario.events:
                engine.observe(event)
            engine.run_cycle(now=1000.0 + time.monotonic(), force=True)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 5.0, "analysis cycles stalled behind model training")
        self.assertEqual(self.wait_for(engine.bootstrap, STATE_ACTIVE), STATE_ACTIVE)


class ModelsAreValidatedBeforeUse(BootstrapHarness):
    @needs_sklearn
    def _trained_engine(self, window=WINDOW, model_dir=None) -> AnalysisEngine:
        engine = self.engine(min_samples=60, window=window, model_dir=model_dir)
        engine.bootstrap.start()
        self.feed_normal(engine, 90)
        self.assertEqual(self.wait_for(engine.bootstrap, STATE_ACTIVE), STATE_ACTIVE)
        return engine

    @needs_sklearn
    def test_a_corrupt_model_file_is_rejected_without_raising(self):
        engine = self._trained_engine()
        engine.model.model_path.write_bytes(b"not a joblib file")
        reason, model, _meta = engine.model.check(
            engine.model.model_path, engine.model.metadata_path)
        self.assertTrue(reason)
        self.assertIsNone(model)

    @needs_sklearn
    def test_a_model_trained_on_a_different_window_is_refused(self):
        """Counts and rates scale with the window, so the scores would be
        confident numbers about a distribution the model never saw."""
        engine = self._trained_engine()
        other = AnomalyEngine(engine.model.model_dir, window_seconds=2.0)
        reason, model, _meta = other.check(engine.model.model_path, engine.model.metadata_path)
        self.assertIn("window", reason)
        self.assertIsNone(model)

    @needs_sklearn
    def test_a_model_with_a_foreign_feature_contract_is_refused(self):
        engine = self._trained_engine()
        metadata = json.loads(engine.model.metadata_path.read_text())
        metadata["feature_names"] = ["something", "else"]
        engine.model.metadata_path.write_text(json.dumps(metadata))
        reason, _model, _meta = engine.model.check(
            engine.model.model_path, engine.model.metadata_path)
        self.assertIn("feature names", reason)

    @needs_sklearn
    def test_checking_a_bad_candidate_leaves_the_active_model_alone(self):
        """check() is pure on purpose: validation happens before promotion."""
        engine = self._trained_engine()
        before = engine.model.status()["metadata"]["model_version"]

        bogus = self.root / "bogus"
        bogus.mkdir()
        (bogus / "anomaly_model.joblib").write_bytes(b"junk")
        (bogus / "anomaly_model.json").write_text("{}")
        reason, _m, _md = engine.model.check(
            bogus / "anomaly_model.joblib", bogus / "anomaly_model.json")

        self.assertTrue(reason)
        self.assertTrue(engine.model.ready)
        self.assertEqual(engine.model.status()["metadata"]["model_version"], before)


class RetrainingIsSafe(BootstrapHarness):
    @needs_sklearn
    def test_a_failed_retrain_keeps_the_model_that_was_working(self):
        engine = self.engine(min_samples=60, retrain_seconds=0.0)
        engine.bootstrap.start()
        self.feed_normal(engine, 90)
        self.assertEqual(self.wait_for(engine.bootstrap, STATE_ACTIVE), STATE_ACTIVE)
        version = engine.model.status()["metadata"]["model_version"]

        import nemos.bootstrap as bootstrap_module

        class ExplodingEngine(AnomalyEngine):
            def train(self, *args, **kwargs):
                raise RuntimeError("simulated training failure")

        original = bootstrap_module.AnomalyEngine
        bootstrap_module.AnomalyEngine = ExplodingEngine
        self.addCleanup(lambda: setattr(bootstrap_module, "AnomalyEngine", original))

        # retrain_seconds=1 with a model trained moments ago is not yet due, so
        # force the run the way the cadence would.
        engine.bootstrap.retrain_seconds = 0.000001
        self.assertTrue(engine.bootstrap.maybe_train())
        self.assertEqual(self.wait_for(engine.bootstrap, STATE_ACTIVE), STATE_ACTIVE)

        self.assertTrue(engine.model.ready, "a failed retrain unloaded the working model")
        self.assertEqual(engine.model.status()["metadata"]["model_version"], version)
        self.assertTrue(engine.model.model_path.is_file())
        self.assertEqual(engine.bootstrap.status()["failures"], 1)
        self.assertIn("simulated training failure", engine.bootstrap.status()["last_error"])

    @needs_sklearn
    def test_retraining_is_not_due_immediately_after_a_fit(self):
        engine = self.engine(min_samples=60, retrain_seconds=86_400.0)
        engine.bootstrap.start()
        self.feed_normal(engine, 90)
        self.assertEqual(self.wait_for(engine.bootstrap, STATE_ACTIVE), STATE_ACTIVE)
        self.assertFalse(engine.bootstrap.maybe_train())
        self.assertEqual(engine.bootstrap.status()["trainings"], 1)

    def test_retraining_can_be_switched_off_entirely(self):
        bootstrap = ModelBootstrap(
            engine=AnomalyEngine(self.root / "model", window_seconds=WINDOW),
            db_path=self.db, window_seconds=WINDOW, retrain_seconds=0.0,
        )
        self.assertFalse(bootstrap._retrain_due(now=time.time()))


class ProgressSurvivesARestart(BootstrapHarness):
    def test_collected_samples_are_reused_by_a_new_process(self):
        """Otherwise every restart resets the observation period, and a sensor
        that is restarted daily never reaches its first model."""
        first = self.engine(min_samples=100_000)
        self.feed_normal(first, 30)
        first.bootstrap.stop(timeout=10)
        collected = self.corpus_size()
        self.assertGreater(collected, 0)

        second = self.engine(min_samples=100_000)
        second.bootstrap.start()
        self.assertEqual(second.bootstrap.status()["samples"], collected)

    @needs_sklearn
    def test_an_automatically_trained_model_is_loaded_on_the_next_start(self):
        first = self.engine(min_samples=60)
        first.bootstrap.start()
        self.feed_normal(first, 90)
        self.assertEqual(self.wait_for(first.bootstrap, STATE_ACTIVE), STATE_ACTIVE)
        version = first.model.status()["metadata"]["model_version"]
        first.bootstrap.stop(timeout=10)

        second = self.engine(min_samples=60)
        self.assertTrue(second.model.load())
        second.bootstrap.start()
        self.assertEqual(second.bootstrap.state, STATE_ACTIVE)
        self.assertEqual(second.model.status()["metadata"]["model_version"], version)

    def test_samples_from_a_different_window_are_never_mixed_in(self):
        """Changing NEMOS_ANALYSIS_WINDOW invalidates the corpus rather than
        producing a model fitted across two incompatible feature scales."""
        first = self.engine(min_samples=100_000, window=WINDOW)
        self.feed_normal(first, 20)
        first.bootstrap.stop(timeout=10)
        self.assertGreater(self.corpus_size(), 0)

        retuned = self.engine(min_samples=100_000, window=2.0)
        self.assertEqual(retuned.bootstrap.status()["samples"], 0)
        self.assertEqual(len(retuned.bootstrap._load_corpus()), 0)


class TheExistingCliStillWorks(BootstrapHarness):
    @needs_sklearn
    def test_train_model_py_trains_from_synthetic_traffic(self):
        """The documented operator command must keep working unchanged."""
        import train_model

        model_dir = self.root / "cli-model"
        code = train_model.main([
            "--source", "synthetic", "--window", "10",
            "--synthetic-windows", "80", "--model-dir", str(model_dir),
        ])
        self.assertEqual(code, 0)
        self.assertTrue((model_dir / "anomaly_model.joblib").is_file())

        engine = AnomalyEngine(model_dir, window_seconds=10.0)
        self.assertTrue(engine.load())

    def test_train_model_py_dry_run_reports_without_fitting(self):
        import train_model

        model_dir = self.root / "cli-dry"
        code = train_model.main([
            "--source", "synthetic", "--window", "10",
            "--synthetic-windows", "20", "--model-dir", str(model_dir), "--dry-run",
        ])
        self.assertEqual(code, 0)
        self.assertFalse((model_dir / "anomaly_model.joblib").exists())


class TheConsoleIsToldTheTruth(BootstrapHarness):
    def test_status_reports_progress_while_warming_up(self):
        engine = self.engine(min_samples=1_000, min_seconds=600.0)
        engine.bootstrap.start()
        self.feed_normal(engine, 20)

        status = engine.status()["bootstrap"]
        self.assertEqual(status["state"], STATE_WARMING_UP)
        self.assertEqual(status["samples_required"], 1_000)
        self.assertEqual(status["observed_seconds_required"], 600.0)
        self.assertGreater(status["samples"], 0)
        self.assertIsNotNone(status["progress"])
        self.assertFalse(status["auto_trained"])
        self.assertEqual(status["algorithm"], "Isolation Forest")

    @needs_sklearn
    def test_status_stops_showing_a_progress_bar_once_active(self):
        engine = self.engine(min_samples=60)
        engine.bootstrap.start()
        self.feed_normal(engine, 90)
        self.assertEqual(self.wait_for(engine.bootstrap, STATE_ACTIVE), STATE_ACTIVE)

        status = engine.status()["bootstrap"]
        self.assertEqual(status["state"], STATE_ACTIVE)
        self.assertIsNone(status["progress"])
        self.assertTrue(status["auto_trained"])

    def test_an_engine_without_a_database_keeps_the_previous_behaviour(self):
        """Callers that construct an engine with no db_path -- tests, the demo,
        anything embedding it -- must not acquire a bootstrap thread."""
        engine = AnalysisEngine(model_dir=self.root / "model", window_seconds=WINDOW)
        self.assertIsNone(engine.bootstrap)
        self.assertEqual(engine.status()["bootstrap"]["state"], STATE_NO_MODEL)


if __name__ == "__main__":
    unittest.main()
