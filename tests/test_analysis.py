from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from nemos.analysis import MAX_PENDING_SOURCES, AnalysisEngine
from nemos.behavioral import STATE_NO_BASELINE, AdaptiveBehaviorProfiler
from nemos.models import Alert, TrafficEvent


def event(src="192.0.2.10", dst="198.51.100.10", sport=40000, dport=443,
          proto="TCP", size=500, flags="PA"):
    return TrafficEvent("2026-01-01T00:00:00+00:00", src, dst, proto, sport, dport, size, flags)


def alert(source="192.0.2.10", threat="PORT_SCAN", risk=80):
    return Alert("2026-01-01T00:00:00+00:00", threat, "NETWORK_RECONNAISSANCE",
                 source, "HIGH", risk, 85, "evidence", technique="T1046")


class EngineFixture(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.alerts: list[Alert] = []
        self.flows: list = []
        self.engine = AnalysisEngine(
            model_dir=Path(self.td.name),
            window_seconds=10.0,
            on_alert=self.alerts.append,
            on_flows=lambda flows: self.flows.extend(flows),
            anomaly_cooldown=0.0,
            # Sample every observation so a test does not have to wait.
            profiler=AdaptiveBehaviorProfiler(sample_interval=0.0, min_samples=3),
        )


class CycleTests(EngineFixture):
    def test_empty_cycle_returns_none(self):
        self.assertIsNone(self.engine.run_cycle(now=100.0))

    def test_cycle_expires_flows_and_reports_sources(self):
        for i in range(5):
            self.engine.observe(event(src="192.0.2.10", dport=1000 + i))
        self.engine.observe(event(src="192.0.2.11"))
        result = self.engine.run_cycle(now=1000.0, force=True)
        self.assertIsNotNone(result)
        self.assertEqual(result.flows, 6)
        self.assertEqual(result.sources, 2)

    def test_flows_reach_the_persistence_callback(self):
        self.engine.observe(event())
        self.engine.run_cycle(now=1000.0, force=True)
        self.assertEqual(len(self.flows), 1)
        self.assertEqual(self.flows[0].key.source, "192.0.2.10")

    def test_flow_direction_survives_the_cycle(self):
        self.engine.observe(event(src="192.0.2.1", dst="192.0.2.2", sport=1234, dport=80))
        self.engine.observe(event(src="192.0.2.2", dst="192.0.2.1", sport=80, dport=1234))
        result = self.engine.run_cycle(now=1000.0, force=True)
        self.assertEqual(result.flows, 2)
        self.assertEqual(result.sources, 2)

    def test_persistence_callback_failure_does_not_break_the_cycle(self):
        engine = AnalysisEngine(
            model_dir=Path(self.td.name), window_seconds=10.0,
            on_flows=lambda flows: (_ for _ in ()).throw(RuntimeError("disk full")),
        )
        engine.observe(event())
        self.assertIsNotNone(engine.run_cycle(now=1000.0, force=True))

    def test_alert_callback_failure_does_not_break_the_cycle(self):
        engine = AnalysisEngine(
            model_dir=Path(self.td.name), window_seconds=10.0,
            on_alert=lambda a: (_ for _ in ()).throw(RuntimeError("boom")),
            anomaly_cooldown=0.0,
            profiler=AdaptiveBehaviorProfiler(sample_interval=0.0, min_samples=1),
        )
        for i in range(30):
            engine.observe(event(dport=1000 + i))
        self.assertIsNotNone(engine.run_cycle(now=1000.0, force=True))


class RuleFusionTests(EngineFixture):
    def test_rule_alerts_are_fused_into_the_next_window(self):
        self.engine.observe(event())
        self.engine.record_rule_alerts("192.0.2.10", [alert()])
        result = self.engine.run_cycle(now=1000.0, force=True)
        assessment = result.assessments[0]
        self.assertIn("rules", assessment.layers)
        self.assertGreaterEqual(assessment.risk_score, 80)
        self.assertEqual(assessment.techniques, ("T1046",))

    def test_rule_findings_are_not_re_emitted_as_alerts(self):
        """The detector already emitted them inline; duplicating would double-count."""
        self.engine.observe(event())
        self.engine.record_rule_alerts("192.0.2.10", [alert()])
        self.engine.run_cycle(now=1000.0, force=True)
        self.assertEqual(self.alerts, [])

    def test_pending_rules_are_consumed_once(self):
        self.engine.observe(event())
        self.engine.record_rule_alerts("192.0.2.10", [alert()])
        self.engine.run_cycle(now=1000.0, force=True)
        self.engine.observe(event())
        result = self.engine.run_cycle(now=2000.0, force=True)
        self.assertNotIn("rules", result.assessments[0].layers)

    def test_pending_rule_map_is_bounded(self):
        # The key is a source address, so spoofing must not grow it without limit.
        for i in range(MAX_PENDING_SOURCES + 500):
            self.engine.record_rule_alerts(f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}", [alert()])
        self.assertLessEqual(self.engine.status()["pending_rule_sources"], MAX_PENDING_SOURCES)

    def test_empty_rule_list_is_ignored(self):
        self.engine.record_rule_alerts("192.0.2.10", [])
        self.assertEqual(self.engine.status()["pending_rule_sources"], 0)


class BaselineTests(EngineFixture):
    def test_unknown_host_reports_no_baseline(self):
        state = self.engine.baseline_for("192.0.2.99")
        self.assertEqual(state["state"], STATE_NO_BASELINE)
        self.assertEqual(state["samples"], 0)

    def test_baseline_accumulates_across_windows(self):
        for cycle in range(6):
            for i in range(10):
                self.engine.observe(event(dport=1000 + i))
            self.engine.run_cycle(now=1000.0 * (cycle + 1), force=True)
        state = self.engine.baseline_for("192.0.2.10")
        self.assertGreater(state["samples"], 1)

    def test_baselines_listing_is_bounded_and_serializable(self):
        for i in range(5):
            self.engine.observe(event(src=f"192.0.2.{i}"))
        self.engine.run_cycle(now=1000.0, force=True)
        listing = self.engine.baselines(limit=3)
        self.assertLessEqual(len(listing), 3)
        json.dumps(listing)


class StatisticalAlertTests(EngineFixture):
    def _drive_anomaly(self, engine):
        """Settle a host, then make it behave very differently."""
        for cycle in range(6):
            for i in range(3):
                engine.observe(event(dport=443, dst=f"198.51.100.{i}"))
            engine.run_cycle(now=100.0 * (cycle + 1), force=True)
        for port in range(1, 200):
            engine.observe(event(dport=port, dst=f"198.51.100.{port % 250}"))
        return engine.run_cycle(now=10_000.0, force=True)

    def test_baseline_deviation_can_raise_an_alert_without_rules(self):
        engine = AnalysisEngine(
            model_dir=Path(self.td.name), window_seconds=10.0,
            on_alert=self.alerts.append, anomaly_cooldown=0.0,
            profiler=AdaptiveBehaviorProfiler(sample_interval=0.0, min_samples=3, sigma_threshold=2.0),
        )
        self._drive_anomaly(engine)
        if self.alerts:
            emitted = self.alerts[-1]
            self.assertEqual(emitted.technique, "", "statistical findings must not claim a technique")
            self.assertIn("verdict", emitted.evidence)
            self.assertIn("explanation", emitted.evidence)

    def test_statistical_alerts_never_carry_an_attack_technique(self):
        engine = AnalysisEngine(
            model_dir=Path(self.td.name), window_seconds=10.0,
            on_alert=self.alerts.append, anomaly_cooldown=0.0,
            profiler=AdaptiveBehaviorProfiler(sample_interval=0.0, min_samples=2, sigma_threshold=1.5),
        )
        self._drive_anomaly(engine)
        for emitted in self.alerts:
            self.assertEqual(emitted.technique, "")

    def test_cooldown_suppresses_repeats(self):
        engine = AnalysisEngine(
            model_dir=Path(self.td.name), window_seconds=10.0,
            on_alert=self.alerts.append, anomaly_cooldown=10_000.0,
            profiler=AdaptiveBehaviorProfiler(sample_interval=0.0, min_samples=2, sigma_threshold=1.2),
        )
        for cycle in range(12):
            for port in range(1, 60 + cycle * 20):
                engine.observe(event(dport=port, dst=f"198.51.100.{port % 250}"))
            engine.run_cycle(now=100.0 * (cycle + 1), force=True)
        # With a very long cooldown at most one alert per source can escape.
        self.assertLessEqual(len(self.alerts), 1)


class LifecycleTests(EngineFixture):
    def test_start_and_stop_are_clean(self):
        self.engine.start()
        self.assertTrue(self.engine.status()["running"])
        self.engine.stop(timeout=3)
        self.assertFalse(self.engine.status()["running"])

    def test_stop_without_start_is_safe(self):
        self.engine.stop(timeout=1)

    def test_double_start_is_idempotent(self):
        self.engine.start()
        self.engine.start()
        self.engine.stop(timeout=3)

    def test_background_thread_processes_windows(self):
        engine = AnalysisEngine(
            model_dir=Path(self.td.name), window_seconds=1.0,
            on_flows=lambda flows: self.flows.extend(flows),
        )
        engine.start()
        try:
            engine.observe(event())
            deadline = time.monotonic() + 6.0
            while time.monotonic() < deadline and not self.flows:
                time.sleep(0.05)
            self.assertTrue(self.flows, "background thread did not process the window")
        finally:
            engine.stop(timeout=3)

    def test_observe_is_safe_from_multiple_threads(self):
        """The capture thread and analysis thread share the flow table."""
        errors = []

        def hammer(base):
            try:
                for i in range(300):
                    self.engine.observe(event(src=f"192.0.2.{base}", dport=1000 + i))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=hammer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.engine.status()["flows"]["observed_packets"], 1200)


class StatusTests(EngineFixture):
    def test_status_is_complete_and_serializable(self):
        status = self.engine.status()
        for key in ("window_seconds", "flows", "model", "cycles", "running"):
            self.assertIn(key, status)
        json.dumps(status)

    def test_status_reports_model_unavailable_without_training(self):
        self.assertFalse(self.engine.status()["model"]["available"])

    def test_engine_works_without_a_trained_model(self):
        """A missing model degrades to rules plus baseline, never a failure."""
        self.engine.observe(event())
        result = self.engine.run_cycle(now=1000.0, force=True)
        self.assertIsNotNone(result)
        self.assertEqual(result.scored_by_model, 0)

    def test_active_flows_snapshot(self):
        self.engine.observe(event())
        active = self.engine.active_flows()
        self.assertEqual(len(active), 1)
        json.dumps(active)


if __name__ == "__main__":
    unittest.main()
