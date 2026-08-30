from __future__ import annotations

import json
import unittest

from nemos.behavioral import (
    STATE_DEVIATING,
    STATE_HIGHLY_DEVIATING,
    STATE_NO_BASELINE,
    STATE_NORMAL,
    BehaviorResult,
)
from nemos.fusion import (
    STATISTICAL_CEILING,
    VERDICT_BENIGN,
    VERDICT_RECON,
    VERDICT_SUSPICIOUS,
    VERDICT_UNUSUAL,
    assess,
    severity_for,
)
from nemos.ml import AnomalyResult


def rule_alert(threat="PORT_SCAN", risk=80, confidence=85, technique="T1046"):
    return {
        "threat": threat, "risk_score": risk, "confidence": confidence,
        "technique": technique, "reason": f"{threat} evidence",
        "evidence": {"ports": [1, 2, 3]},
    }


def anomaly(score=95, band="HIGHLY_ANOMALOUS"):
    return AnomalyResult(
        source="192.0.2.10", anomaly_score=score, band=band, raw_score=-0.4,
        model_version="1.1.0",
        contributing_features=(("destination_port_entropy", 6.2), ("syn_ratio", 4.1)),
    )


def baseline(state=STATE_DEVIATING, sigma=4.2, samples=30):
    return BehaviorResult(
        ready=state in (STATE_DEVIATING, STATE_HIGHLY_DEVIATING),
        anomaly_score=70, confidence=80,
        deviations={"rate": sigma, "unique_ports": 3.1},
        baseline={"rate": 2.0, "samples": samples},
        state=state, strongest_sigma=sigma, samples=samples,
    )


class NoEvidenceTests(unittest.TestCase):
    def test_nothing_fired_is_benign(self):
        result = assess("192.0.2.10")
        self.assertEqual(result.verdict, VERDICT_BENIGN)
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.confidence, 0)
        self.assertFalse(result.actionable)

    def test_normal_baseline_and_low_anomaly_stay_benign(self):
        result = assess("192.0.2.10", anomaly=anomaly(score=5, band="NORMAL"),
                        baseline=baseline(state=STATE_NORMAL))
        self.assertEqual(result.verdict, VERDICT_BENIGN)
        self.assertEqual(result.risk_score, 0)

    def test_no_baseline_host_is_not_called_anomalous(self):
        """A host with no history must never be judged on that absence."""
        result = assess("192.0.2.10", baseline=BehaviorResult(
            False, 0, 0, {}, {}, state=STATE_NO_BASELINE, samples=2))
        self.assertEqual(result.verdict, VERDICT_BENIGN)
        self.assertEqual(result.baseline_state, STATE_NO_BASELINE)


class StatisticalOnlyTests(unittest.TestCase):
    """Statistical evidence alone says "unusual", never "hostile"."""

    def test_ml_alone_cannot_reach_critical(self):
        result = assess("192.0.2.10", anomaly=anomaly(score=100))
        self.assertLessEqual(result.risk_score, STATISTICAL_CEILING)
        self.assertNotEqual(result.severity, "CRITICAL")

    def test_ml_plus_baseline_still_cannot_reach_critical(self):
        result = assess("192.0.2.10", anomaly=anomaly(score=100),
                        baseline=baseline(state=STATE_HIGHLY_DEVIATING, sigma=9.0))
        self.assertLessEqual(result.risk_score, STATISTICAL_CEILING)
        self.assertNotEqual(result.severity, "CRITICAL")

    def test_ml_alone_assigns_no_attack_technique(self):
        """An anomaly score is not evidence of a named adversary technique."""
        result = assess("192.0.2.10", anomaly=anomaly(score=99),
                        baseline=baseline(state=STATE_HIGHLY_DEVIATING))
        self.assertEqual(result.techniques, ())

    def test_ml_alone_uses_hedged_verdict_wording(self):
        result = assess("192.0.2.10", anomaly=anomaly(score=75))
        self.assertIn(result.verdict, (VERDICT_UNUSUAL, VERDICT_SUSPICIOUS))

    def test_statistical_confidence_is_capped(self):
        result = assess("192.0.2.10", anomaly=anomaly(score=100),
                        baseline=baseline(state=STATE_HIGHLY_DEVIATING, samples=500))
        self.assertLessEqual(result.confidence, 75)

    def test_anomaly_below_normal_band_contributes_nothing(self):
        result = assess("192.0.2.10", anomaly=anomaly(score=10, band="NORMAL"))
        signal = next(s for s in result.signals if s.layer == "ml")
        self.assertEqual(signal.contribution, 0)


class RuleFloorTests(unittest.TestCase):
    def test_rule_risk_is_the_floor(self):
        result = assess("192.0.2.10", rule_alerts=[rule_alert(risk=80)])
        self.assertGreaterEqual(result.risk_score, 80)

    def test_statistical_layers_only_ever_raise(self):
        alone = assess("192.0.2.10", rule_alerts=[rule_alert(risk=80)]).risk_score
        combined = assess("192.0.2.10", rule_alerts=[rule_alert(risk=80)],
                          anomaly=anomaly(score=95),
                          baseline=baseline(state=STATE_HIGHLY_DEVIATING)).risk_score
        self.assertGreaterEqual(combined, alone)

    def test_rules_plus_statistics_can_reach_critical(self):
        result = assess("192.0.2.10", rule_alerts=[rule_alert(risk=88)],
                        anomaly=anomaly(score=98),
                        baseline=baseline(state=STATE_HIGHLY_DEVIATING))
        self.assertEqual(result.severity, "CRITICAL")

    def test_strongest_rule_wins_not_the_sum(self):
        result = assess("192.0.2.10", rule_alerts=[
            rule_alert(risk=60), rule_alert(threat="DNS_BURST", risk=70, technique="T1071.004")
        ])
        # 70 floor, not 130.
        self.assertLess(result.risk_score, 100)
        self.assertGreaterEqual(result.risk_score, 70)

    def test_techniques_come_from_rules_and_are_deduplicated(self):
        result = assess("192.0.2.10", rule_alerts=[
            rule_alert(technique="T1046"), rule_alert(threat="TCP_SYN_SCAN", technique="T1046"),
            rule_alert(threat="DNS_BURST", technique="T1071.004"),
        ])
        self.assertEqual(sorted(result.techniques), ["T1046", "T1071.004"])

    def test_unmapped_rule_contributes_no_technique(self):
        result = assess("192.0.2.10", rule_alerts=[
            rule_alert(threat="BEHAVIORAL_TRAFFIC_ANOMALY", technique="")
        ])
        self.assertEqual(result.techniques, ())

    def test_recon_threats_produce_a_recon_verdict(self):
        self.assertEqual(assess("x", rule_alerts=[rule_alert("PORT_SCAN")]).verdict, VERDICT_RECON)
        self.assertEqual(assess("x", rule_alerts=[rule_alert("ICMP_SWEEP")]).verdict, VERDICT_RECON)


class CorroborationTests(unittest.TestCase):
    def test_agreeing_layers_add_a_bounded_bonus(self):
        one = assess("x", anomaly=anomaly(score=80)).risk_score
        two = assess("x", anomaly=anomaly(score=80),
                     baseline=baseline(state=STATE_DEVIATING)).risk_score
        self.assertGreater(two, one)

    def test_corroboration_is_recorded_as_a_reason(self):
        result = assess("x", rule_alerts=[rule_alert()], anomaly=anomaly(score=80))
        self.assertTrue(any("agree" in r for r in result.reasons))

    def test_single_layer_gets_no_bonus(self):
        result = assess("x", anomaly=anomaly(score=80))
        self.assertEqual(result.explanation["corroboration_bonus"], 0)


class ExplainabilityTests(unittest.TestCase):
    def test_arithmetic_is_reproducible_by_hand(self):
        result = assess("x", rule_alerts=[rule_alert(risk=70)],
                        anomaly=anomaly(score=90),
                        baseline=baseline(state=STATE_DEVIATING))
        e = result.explanation
        recomputed = (e["rule_floor"] + e["ml_contribution"]
                      + e["baseline_contribution"] + e["corroboration_bonus"])
        self.assertEqual(recomputed, e["subtotal"])
        self.assertEqual(min(e["subtotal"], e["ceiling"]), result.risk_score)

    def test_every_signal_reports_its_own_contribution(self):
        result = assess("x", rule_alerts=[rule_alert()], anomaly=anomaly(),
                        baseline=baseline())
        layers = {s.layer for s in result.signals}
        self.assertEqual(layers, {"rules", "ml", "baseline"})
        for signal in result.signals:
            self.assertIsInstance(signal.contribution, int)

    def test_reasons_are_human_readable_and_deduplicated(self):
        result = assess("x", rule_alerts=[rule_alert()], anomaly=anomaly(),
                        baseline=baseline())
        self.assertTrue(result.reasons)
        self.assertEqual(len(result.reasons), len(set(result.reasons)))
        for reason in result.reasons:
            self.assertIsInstance(reason, str)
            self.assertGreater(len(reason), 5)

    def test_explanation_states_why_the_ceiling_applies(self):
        statistical = assess("x", anomaly=anomaly(score=99))
        self.assertIn("not that it is hostile", statistical.explanation["ceiling_reason"])
        deterministic = assess("x", rule_alerts=[rule_alert()])
        self.assertIn("full range", deterministic.explanation["ceiling_reason"])

    def test_explanation_states_attack_mapping_provenance(self):
        result = assess("x", anomaly=anomaly())
        self.assertIn("deterministic rules only", result.explanation["attack_mapping_source"])

    def test_assessment_is_json_serializable(self):
        result = assess("x", rule_alerts=[rule_alert()], anomaly=anomaly(), baseline=baseline())
        json.dumps(result.as_dict())

    def test_detection_layers_are_reported(self):
        result = assess("x", rule_alerts=[rule_alert()], anomaly=anomaly())
        self.assertEqual(result.as_dict()["detection_layers"], ["ml", "rules"])


class SeverityTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(severity_for(95), "CRITICAL")
        self.assertEqual(severity_for(80), "HIGH")
        self.assertEqual(severity_for(60), "MEDIUM")
        self.assertEqual(severity_for(10), "LOW")

    def test_risk_is_always_bounded(self):
        result = assess("x", rule_alerts=[rule_alert(risk=100)], anomaly=anomaly(score=100),
                        baseline=baseline(state=STATE_HIGHLY_DEVIATING))
        self.assertLessEqual(result.risk_score, 100)
        self.assertGreaterEqual(result.risk_score, 0)


if __name__ == "__main__":
    unittest.main()
