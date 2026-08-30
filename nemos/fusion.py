"""Combine deterministic, statistical and ML evidence into one assessment.

NEMOS has three independent detection layers, and they are not
interchangeable:

``rules``
    Deterministic thresholds over observed traffic. When one fires it is
    because a specific, named behaviour was observed -- 259 destination ports
    in ten seconds, an ARP mapping that changed. This is the strongest kind of
    evidence NEMOS has, and the only kind that can justify a MITRE ATT&CK
    technique.

``baseline``
    A per-source exponentially weighted statistical model. It establishes that
    a host is behaving unlike *itself*.

``ml``
    An Isolation Forest over per-window flow features. It establishes that a
    window is unlike the traffic the model was *trained on*.

The last two say traffic is unusual. Neither says it is hostile, and the fusion
rules below encode that distinction rather than blurring it:

1. **Rules set the floor.** A deterministic finding's own risk is the starting
   point; statistical layers can raise it but never lower it.
2. **Statistical evidence alone is capped below CRITICAL.** Without a
   deterministic finding, the assessment cannot exceed ``STATISTICAL_CEILING``.
   "This is unusual" is not "this is an attack", and a score of 95 would claim
   otherwise.
3. **ATT&CK mapping comes only from rules.** An anomaly score never produces a
   technique ID. A model that cannot name a behaviour cannot evidence one.
4. **Corroboration is worth something, but bounded.** Independent layers
   agreeing is genuine evidence; it is not a licence to add scores together.

Every number in the result carries the arithmetic that produced it, in
``explanation``. If a reviewer cannot reproduce a risk score by hand from the
signals, that is a bug in this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from collections.abc import Mapping, Sequence

from .behavioral import (
    STATE_DEVIATING,
    STATE_HIGHLY_DEVIATING,
    STATE_NO_BASELINE,
    BehaviorResult,
)
from .ml import BAND_NORMAL, BAND_SUSPICIOUS, AnomalyResult

LAYER_RULES = "rules"
LAYER_BASELINE = "baseline"
LAYER_ML = "ml"

#: Statistical layers alone cannot reach CRITICAL (>= 90). See rule 2 above.
STATISTICAL_CEILING = 84

#: Maximum a single layer may contribute on top of the deterministic floor.
ML_MAX_CONTRIBUTION = 25
BASELINE_MAX_CONTRIBUTION = 15
CORROBORATION_BONUS = 10

#: Baseline state to its contribution when supporting a rule finding.
BASELINE_CONTRIBUTION = {
    STATE_HIGHLY_DEVIATING: BASELINE_MAX_CONTRIBUTION,
    STATE_DEVIATING: 8,
}

#: Baseline state to risk when it is the *only* evidence. Higher than the
#: supporting contribution above, because here it must carry the finding on its
#: own rather than nudge one that already exists.
STATISTICAL_BASELINE_RISK = {
    STATE_HIGHLY_DEVIATING: 55,
    STATE_DEVIATING: 35,
}

#: Verdict wording. Deliberately describes what was observed rather than
#: asserting intent -- NEMOS sees traffic, not motives.
VERDICT_BENIGN = "NO_FINDING"
VERDICT_UNUSUAL = "UNUSUAL_TRAFFIC"
VERDICT_SUSPICIOUS = "SUSPICIOUS_BEHAVIOR"
VERDICT_RECON = "POSSIBLE_RECONNAISSANCE"
VERDICT_ATTACK_PATTERN = "BEHAVIOR_CONSISTENT_WITH_ATTACK"

#: Threat names whose observed evidence is reconnaissance-shaped.
_RECON_THREATS = {
    "PORT_SCAN", "TCP_SYN_SCAN", "UDP_PORT_SCAN", "ICMP_SWEEP",
    "NETWORK_FANOUT", "SERVICE_CONNECTION_BURST",
}


@dataclass(frozen=True, slots=True)
class Signal:
    """One layer's contribution, with the reasons it produced."""

    layer: str
    name: str
    score: int
    contribution: int
    reasons: tuple[str, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "name": self.name,
            "score": self.score,
            "contribution": self.contribution,
            "reasons": list(self.reasons),
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class Assessment:
    """The fused view of one source over one window."""

    source: str
    risk_score: int
    confidence: int
    severity: str
    verdict: str
    signals: tuple[Signal, ...]
    reasons: tuple[str, ...]
    techniques: tuple[str, ...]
    baseline_state: str
    anomaly_score: int | None
    explanation: Mapping[str, Any]

    @property
    def actionable(self) -> bool:
        return self.verdict != VERDICT_BENIGN

    @property
    def layers(self) -> tuple[str, ...]:
        return tuple(sorted({s.layer for s in self.signals}))

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "severity": self.severity,
            "verdict": self.verdict,
            "baseline_state": self.baseline_state,
            "anomaly_score": self.anomaly_score,
            "detection_layers": list(self.layers),
            "signals": [s.as_dict() for s in self.signals],
            "reasons": list(self.reasons),
            "techniques": list(self.techniques),
            "explanation": dict(self.explanation),
        }


def severity_for(risk: int) -> str:
    return "CRITICAL" if risk >= 90 else "HIGH" if risk >= 75 else "MEDIUM" if risk >= 50 else "LOW"


def _ml_contribution(anomaly_score: int) -> int:
    """Corroboration bonus for an anomaly score, on top of a rule finding.

    This is the *supporting* role: a rule has already established a specific
    behaviour and the model agrees the window is unusual. Below
    ``BAND_NORMAL`` the model considers the window ordinary and contributes
    nothing at all -- not a small amount, nothing.
    """
    if anomaly_score < BAND_NORMAL:
        return 0
    span = max(1, 100 - BAND_NORMAL)
    return int(round(ML_MAX_CONTRIBUTION * (anomaly_score - BAND_NORMAL) / span))


def _statistical_risk(anomaly_score: int | None, baseline_state: str) -> int:
    """Risk when statistics are the *only* evidence, with no rule finding.

    A separate mapping from :func:`_ml_contribution`, because the two answer
    different questions. As a bonus, any deviation above the NORMAL band adds
    something. As the sole basis for an alert, it must not: a window sitting in
    the merely-SUSPICIOUS band is the ordinary jitter of real traffic, and
    alerting on it produces noise that trains operators to ignore the sensor.

    So nothing below ``BAND_SUSPICIOUS`` contributes at all, and the two
    statistical views are combined with ``max`` rather than a sum -- an unusual
    window and a deviating host are usually two views of one underlying change,
    and adding them would double-count it.
    """
    ml_part = 0
    if anomaly_score is not None and anomaly_score >= BAND_SUSPICIOUS:
        span = max(1, 100 - BAND_SUSPICIOUS)
        ml_part = int(round(45 + (STATISTICAL_CEILING - 45)
                            * (anomaly_score - BAND_SUSPICIOUS) / span))
    baseline_part = STATISTICAL_BASELINE_RISK.get(baseline_state, 0)
    if not ml_part and not baseline_part:
        return 0
    both = ml_part > 0 and baseline_part > 0
    return min(STATISTICAL_CEILING, max(ml_part, baseline_part) + (CORROBORATION_BONUS if both else 0))


def _ml_reasons(result: AnomalyResult) -> tuple[str, ...]:
    """Turn the model's unusual features into readable statements."""
    reasons = [
        f"traffic pattern is unlike the trained baseline "
        f"(anomaly score {result.anomaly_score}/100, {result.band.lower().replace('_', ' ')})"
    ]
    for name, z in result.contributing_features[:3]:
        direction = "above" if z > 0 else "below"
        reasons.append(
            f"{name.replace('_', ' ')} is {abs(z):.1f} standard deviations {direction} "
            f"the training mean"
        )
    return tuple(reasons)


def _baseline_reasons(result: BehaviorResult) -> tuple[str, ...]:
    reasons = [
        f"host behaviour deviates from its own baseline "
        f"({result.strongest_sigma:.1f} sigma, {result.samples} observations)"
    ]
    ranked = sorted(result.deviations.items(), key=lambda kv: kv[1], reverse=True)
    for name, sigma in ranked[:2]:
        if sigma > 0:
            reasons.append(f"{name.replace('_', ' ')} deviates by {sigma:.1f} sigma")
    return tuple(reasons)


def _verdict_for(rule_threats: Sequence[str], risk: int, has_rules: bool) -> str:
    if not has_rules:
        return VERDICT_UNUSUAL if risk < 50 else VERDICT_SUSPICIOUS
    if any(threat in _RECON_THREATS for threat in rule_threats):
        return VERDICT_RECON
    return VERDICT_ATTACK_PATTERN if risk >= 75 else VERDICT_SUSPICIOUS


def assess(source: str,
           rule_alerts: Sequence[Mapping[str, Any]] = (),
           anomaly: AnomalyResult | None = None,
           baseline: BehaviorResult | None = None) -> Assessment:
    """Fuse the available evidence for one source into a single assessment.

    ``rule_alerts`` are alert dictionaries from the deterministic detector.
    ``anomaly`` and ``baseline`` may each be ``None`` -- the model may be
    untrained and the host may have no baseline yet, and neither is an error.
    """
    signals: list[Signal] = []
    reasons: list[str] = []
    techniques: list[str] = []

    # --- deterministic layer: sets the floor -----------------------------
    rule_risk = 0
    rule_confidence = 0
    rule_threats: list[str] = []
    for alert in rule_alerts:
        threat = str(alert.get("threat") or "")
        risk = int(alert.get("risk_score") or 0)
        rule_threats.append(threat)
        rule_risk = max(rule_risk, risk)
        rule_confidence = max(rule_confidence, int(alert.get("confidence") or 0))
        technique = str(alert.get("technique") or "").strip()
        if technique and technique not in techniques:
            techniques.append(technique)
        reason = str(alert.get("reason") or "").strip()
        signals.append(Signal(
            layer=LAYER_RULES,
            name=threat,
            score=risk,
            contribution=risk,
            reasons=(reason,) if reason else (),
            evidence=alert.get("evidence") or {},
        ))
        if reason:
            reasons.append(f"{threat}: {reason}")

    has_rules = bool(rule_alerts)

    # --- ML layer --------------------------------------------------------
    ml_contribution = 0
    anomaly_score = None
    if anomaly is not None:
        anomaly_score = anomaly.anomaly_score
        ml_contribution = _ml_contribution(anomaly.anomaly_score)
        ml_reasons = _ml_reasons(anomaly)
        signals.append(Signal(
            layer=LAYER_ML,
            name="ML_ANOMALY",
            score=anomaly.anomaly_score,
            contribution=ml_contribution,
            reasons=ml_reasons,
            evidence={
                "band": anomaly.band,
                "model_version": anomaly.model_version,
                "contributing_features": [
                    {"feature": n, "z_from_training_mean": round(z, 3)}
                    for n, z in anomaly.contributing_features
                ],
            },
        ))
        if ml_contribution > 0:
            reasons.extend(ml_reasons)

    # --- baseline layer --------------------------------------------------
    baseline_contribution = 0
    baseline_state = STATE_NO_BASELINE
    if baseline is not None:
        baseline_state = baseline.state
        baseline_contribution = BASELINE_CONTRIBUTION.get(baseline.state, 0)
        base_reasons = _baseline_reasons(baseline) if baseline_contribution else ()
        signals.append(Signal(
            layer=LAYER_BASELINE,
            name="BEHAVIORAL_BASELINE",
            score=baseline.anomaly_score,
            contribution=baseline_contribution,
            reasons=base_reasons,
            evidence={
                "state": baseline.state,
                "strongest_sigma": baseline.strongest_sigma,
                "samples": baseline.samples,
                "deviations_sigma": dict(baseline.deviations),
                "baseline": dict(baseline.baseline),
            },
        ))
        reasons.extend(base_reasons)

    # --- combine ---------------------------------------------------------
    statistical_layers = sum(1 for c in (ml_contribution, baseline_contribution) if c > 0)
    ceiling = 100 if has_rules else STATISTICAL_CEILING

    if has_rules:
        # Rules set the floor; statistics corroborate and may raise it.
        corroboration = CORROBORATION_BONUS if statistical_layers >= 1 else 0
        raw = rule_risk + ml_contribution + baseline_contribution + corroboration
    else:
        # No deterministic finding: statistics must carry the assessment alone,
        # under a stricter mapping and a lower ceiling.
        raw = _statistical_risk(anomaly_score, baseline_state)
        corroboration = 0
        ml_contribution = raw if anomaly_score is not None and raw else 0
        baseline_contribution = 0

    risk = max(0, min(ceiling, raw))
    verdict = VERDICT_BENIGN if risk == 0 else _verdict_for(rule_threats, risk, has_rules)
    if verdict == VERDICT_BENIGN:
        risk = 0
        reasons = []
    elif corroboration:
        reasons.append("independent detection layers agree on this source")

    # Confidence: deterministic findings carry their own; a purely statistical
    # assessment is capped, because "unlike training data" is a weaker claim
    # than "this specific behaviour was observed".
    if has_rules:
        confidence = min(99, rule_confidence + (5 if statistical_layers else 0))
    elif verdict == VERDICT_BENIGN:
        confidence = 0
    else:
        statistical_confidence = 40 + (ml_contribution + baseline_contribution)
        if baseline is not None and baseline.state != STATE_NO_BASELINE:
            statistical_confidence += min(10, baseline.samples // 4)
        confidence = min(75, statistical_confidence)

    explanation = {
        "method": (
            "risk = strongest rule risk + ML contribution + baseline contribution "
            "+ corroboration bonus, capped at the applicable ceiling"
            if has_rules else
            "no rule fired: risk = max(ML tail risk, baseline risk) + corroboration "
            "when both fired, capped below CRITICAL"
        ),
        "rule_floor": rule_risk,
        "ml_contribution": ml_contribution,
        "baseline_contribution": baseline_contribution,
        "corroboration_bonus": corroboration,
        "subtotal": raw,
        "ceiling": ceiling,
        "ceiling_reason": (
            "a deterministic detection is present, so the full range is available"
            if has_rules else
            "no deterministic detection: statistical evidence alone establishes that "
            "traffic is unusual, not that it is hostile, so the score cannot reach CRITICAL"
        ),
        "final_risk": risk,
        "attack_mapping_source": (
            "deterministic rules only; ML and baseline never assign a technique"
        ),
    }

    return Assessment(
        source=source,
        risk_score=risk,
        confidence=confidence,
        severity=severity_for(risk),
        verdict=verdict,
        signals=tuple(signals),
        reasons=tuple(dict.fromkeys(reasons)),  # de-duplicate, keep order
        techniques=tuple(techniques),
        baseline_state=baseline_state,
        anomaly_score=anomaly_score,
        explanation=explanation,
    )


__all__ = [
    "BASELINE_MAX_CONTRIBUTION",
    "CORROBORATION_BONUS",
    "LAYER_BASELINE",
    "LAYER_ML",
    "LAYER_RULES",
    "ML_MAX_CONTRIBUTION",
    "STATISTICAL_CEILING",
    "VERDICT_ATTACK_PATTERN",
    "VERDICT_BENIGN",
    "VERDICT_RECON",
    "VERDICT_SUSPICIOUS",
    "VERDICT_UNUSUAL",
    "Assessment",
    "Signal",
    "assess",
    "severity_for",
]
