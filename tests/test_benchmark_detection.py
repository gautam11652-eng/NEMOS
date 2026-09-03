"""Tests for the detection benchmark.

A benchmark nobody checks is decoration. The properties that matter here are
not "does it print a table" but:

- ground truth is coherent, and names findings the detector can actually emit;
- the arithmetic is right, including the cases where a metric is undefined
  rather than zero;
- an expected *set* means "any of these", so an unfired alternative is not
  charged as a miss -- an earlier version reported two detections at 0% recall
  for shapes they were never required to catch;
- and above all, that it can register a regression. A benchmark that only ever
  prints 100% measures nothing.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for candidate in (ROOT, ROOT / "tools"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from tools.benchmark_detection import Counts, evaluate, replay  # noqa: E402
from tools.scenarios import (  # noqa: E402
    ATTACK_SCENARIOS,
    BENIGN_SCENARIOS,
    SCENARIOS,
    build,
)

from nemos.detector import DetectionConfig, ThreatDetector  # noqa: E402


def emitted_threat_names() -> set[str]:
    """Every threat name the detector can produce, read from its source."""
    import re
    source = (ROOT / "nemos" / "detector.py").read_text()
    return set(re.findall(r'"([A-Z][A-Z0-9_]{4,})", "[A-Z_]+"', source))


class GroundTruthTests(unittest.TestCase):
    def test_benign_and_expected_agree(self):
        """`benign` is derived from `expected`; they cannot disagree."""
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                scenario = build(name)
                self.assertEqual(scenario.benign, not scenario.expected)

    def test_every_scenario_is_classified(self):
        self.assertEqual(
            set(BENIGN_SCENARIOS) | set(ATTACK_SCENARIOS), set(SCENARIOS))
        self.assertFalse(set(BENIGN_SCENARIOS) & set(ATTACK_SCENARIOS))

    def test_benign_scenarios_expect_nothing(self):
        for name in BENIGN_SCENARIOS:
            with self.subTest(scenario=name):
                self.assertEqual(build(name).expected, ())

    def test_attack_scenarios_expect_something(self):
        for name in ATTACK_SCENARIOS:
            with self.subTest(scenario=name):
                self.assertTrue(build(name).expected)

    def test_expected_names_are_findings_the_detector_can_emit(self):
        """A label naming a threat that does not exist can never be satisfied,
        so it would report a permanent, unfixable false negative."""
        real = emitted_threat_names()
        for name in ATTACK_SCENARIOS:
            for threat in build(name).expected:
                with self.subTest(scenario=name, threat=threat):
                    self.assertIn(threat, real)

    def test_the_hard_benign_corpus_is_actually_busy(self):
        """`normal` is paced below the thresholds by construction, so a
        false-positive rate measured against it alone is close to circular."""
        for name in ("nat_gateway", "monitoring_host", "backup_window"):
            with self.subTest(scenario=name):
                self.assertGreater(len(build(name)), 100)


class CountsTests(unittest.TestCase):
    def test_precision_recall_and_f1(self):
        counts = Counts(true_positive=3, false_positive=1, false_negative=1)
        self.assertAlmostEqual(counts.precision, 0.75)
        self.assertAlmostEqual(counts.recall, 0.75)
        self.assertAlmostEqual(counts.f1, 0.75)

    def test_an_unasked_detector_has_undefined_precision_not_zero(self):
        """0.00 would read as "always wrong"; the truth is "never fired"."""
        self.assertIsNone(Counts().precision)
        self.assertIsNone(Counts().recall)
        self.assertIsNone(Counts().f1)

    def test_firing_elsewhere_does_not_touch_precision(self):
        """A finding on *malicious* traffic labelled as something else is not
        an unambiguous error, so it is reported separately, not folded in."""
        counts = Counts(true_positive=2, fired_elsewhere=9)
        self.assertEqual(counts.precision, 1.0)
        self.assertEqual(counts.as_dict()["fired_on_other_malicious"], 9)

    def test_a_false_positive_does_lower_precision(self):
        self.assertAlmostEqual(
            Counts(true_positive=1, false_positive=1).precision, 0.5)

    def test_the_dict_separates_the_two_false_positive_populations(self):
        body = Counts(false_positive=2, fired_elsewhere=3).as_dict()
        self.assertEqual(body["false_positive_benign"], 2)
        self.assertEqual(body["fired_on_other_malicious"], 3)


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.config = DetectionConfig.from_env()

    def test_replay_uses_scenario_time_not_wall_clock(self):
        """Replaying ten seconds of traffic in milliseconds would put every
        event in one window and manufacture findings."""
        scenario = build("normal")
        offsets = [offset for offset, _ in replay(scenario, self.config)]
        for offset in offsets:
            self.assertLessEqual(offset, scenario.duration + 1)

    def test_each_replay_starts_from_a_clean_detector(self):
        """Cooldown and incident state carry across findings, so a shared
        detector would let one replay suppress the next."""
        scenario = build("port_sweep")
        first = replay(scenario, self.config)
        second = replay(scenario, self.config)
        self.assertEqual({t for _, t in first}, {t for _, t in second})
        self.assertTrue(first)

    def test_a_quiet_scenario_produces_no_finding(self):
        self.assertEqual(replay(build("normal"), self.config), [])


class EvaluateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = evaluate(1, DetectionConfig.from_env())

    def test_it_reports_the_documented_shape(self):
        for key in ("nemos_version", "repeats", "overall", "per_detection",
                    "per_scenario", "median_latency_seconds",
                    "false_positives_per_benign_replay"):
            self.assertIn(key, self.data)

    def test_every_scenario_is_replayed(self):
        names = {item["scenario"] for item in self.data["per_scenario"]}
        self.assertEqual(names, set(SCENARIOS))

    def test_no_alternative_label_is_charged_a_phantom_miss(self):
        """An expected set means "any of these is acceptable". Charging every
        unfired member an FN reported LATERAL_MOVEMENT and
        DNS_TUNNELING_PATTERN at 0% recall for shapes they never had to catch.
        """
        for item in self.data["per_scenario"]:
            if item["benign"] or not item["detected"]:
                continue
            fired = set(item["findings"])
            unfired = [t for t in item["expected"] if t not in fired]
            for threat in unfired:
                counts = self.data["per_detection"].get(threat)
                if counts is not None:
                    with self.subTest(scenario=item["scenario"], threat=threat):
                        self.assertEqual(counts["false_negative"], 0)

    def test_metrics_stay_within_range(self):
        for name, counts in self.data["per_detection"].items():
            for metric in ("precision", "recall", "f1"):
                value = counts[metric]
                if value is not None:
                    with self.subTest(detection=name, metric=metric):
                        self.assertGreaterEqual(value, 0.0)
                        self.assertLessEqual(value, 1.0)

    def test_latency_is_measured_in_scenario_seconds(self):
        for item in self.data["per_scenario"]:
            latency = item["median_latency_seconds"]
            if latency is not None:
                with self.subTest(scenario=item["scenario"]):
                    self.assertGreaterEqual(latency, 0.0)
                    self.assertLess(latency, 600.0)

    def test_the_benign_corpus_is_scored_for_false_positives(self):
        """Whatever the number is, it has to be measured rather than assumed."""
        self.assertIsNotNone(self.data["false_positives_per_benign_replay"])

    def test_results_are_json_serialisable(self):
        import json
        json.loads(json.dumps(self.data))


class RegressionSensitivityTests(unittest.TestCase):
    """The property that makes the benchmark worth running at all."""

    def test_a_crippled_threshold_lowers_recall(self):
        healthy = evaluate(1, DetectionConfig.from_env())
        crippled = evaluate(1, DetectionConfig(port_scan=100_000))

        healthy_sweep = next(i for i in healthy["per_scenario"]
                             if i["scenario"] == "port_sweep")
        crippled_sweep = next(i for i in crippled["per_scenario"]
                              if i["scenario"] == "port_sweep")

        self.assertEqual(healthy_sweep["detection_rate"], 1.0)
        self.assertEqual(crippled_sweep["detection_rate"], 0.0)
        self.assertLess(crippled["overall"]["recall"], healthy["overall"]["recall"])

    def test_a_crippled_threshold_is_attributed_to_the_right_detection(self):
        crippled = evaluate(1, DetectionConfig(port_scan=100_000))
        port_scan = crippled["per_detection"].get("PORT_SCAN", {})
        self.assertEqual(port_scan.get("recall"), 0.0)
        # And the detections that were not crippled are unaffected.
        self.assertEqual(crippled["per_detection"]["ICMP_SWEEP"]["recall"], 1.0)


class SafetyTests(unittest.TestCase):
    def test_every_address_is_a_documentation_address(self):
        """RFC 5737 ranges are not routable, so a mistake cannot reach a host."""
        allowed = ("192.0.2.", "198.51.100.", "203.0.113.")
        for name in SCENARIOS:
            scenario = build(name)
            for _, event in scenario.events:
                if not (event.source.startswith(allowed)
                        and event.destination.startswith(allowed)):
                    self.fail(f"{name}: {event.source} -> {event.destination}")

    def test_the_detector_is_driven_directly_with_no_sockets(self):
        detector = ThreatDetector(DetectionConfig.from_env())
        self.assertFalse(hasattr(detector, "socket"))


if __name__ == "__main__":
    unittest.main()
