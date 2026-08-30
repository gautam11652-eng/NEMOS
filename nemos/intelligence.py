from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable, Mapping
import json


@dataclass(frozen=True, slots=True)
class IncidentSummary:
    incident_id: str
    risk_score: int
    severity: str
    confidence: int
    alert_count: int
    unique_threats: int
    unique_techniques: int
    critical_alerts: int
    sources: tuple[str, ...]
    threats: tuple[str, ...]
    techniques: tuple[str, ...]
    evidence_signals: int
    recommendations: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "confidence": self.confidence,
            "alert_count": self.alert_count,
            "unique_threats": self.unique_threats,
            "unique_techniques": self.unique_techniques,
            "critical_alerts": self.critical_alerts,
            "sources": list(self.sources),
            "threats": list(self.threats),
            "techniques": list(self.techniques),
            "evidence_signals": self.evidence_signals,
            "recommendations": list(self.recommendations),
        }


def summarize_incident(incident_id: str, alerts: Iterable[Mapping[str, Any]]) -> IncidentSummary:
    """Build an explainable incident-level triage score.

    This is deliberately deterministic. It combines the strongest alert with
    independent signals (distinct detections, techniques, critical findings,
    and evidence) rather than claiming that the score is a probability of
    compromise.
    """
    rows = list(alerts)
    if not rows:
        raise ValueError("incident requires at least one alert")

    threats = tuple(sorted({str(r.get("threat") or "") for r in rows if r.get("threat")}))
    techniques = tuple(sorted({str(r.get("technique") or "") for r in rows if r.get("technique")}))
    sources = tuple(sorted({str(r.get("source") or "") for r in rows if r.get("source")}))
    max_risk = max(int(r.get("risk_score") or 0) for r in rows)
    critical = sum(1 for r in rows if str(r.get("severity", "")).upper() == "CRITICAL")
    confidence_values = [max(0, min(100, int(r.get("confidence") or 0))) for r in rows]
    avg_confidence = round(sum(confidence_values) / len(confidence_values))

    # Reward independent evidence, but keep the score bounded and explainable.
    diversity_bonus = min(18, max(0, len(threats) - 1) * 6)
    technique_bonus = min(10, max(0, len(techniques) - 1) * 5)
    critical_bonus = min(12, critical * 6)
    evidence_signals = 0
    for row in rows:
        evidence = row.get("evidence")
        if isinstance(evidence, dict):
            evidence_signals += min(5, len(evidence))
        elif isinstance(evidence, str) and evidence not in ("", "{}"):  # DB representation
            try:
                parsed = json.loads(evidence)
            except (TypeError, ValueError):
                parsed = None
            evidence_signals += min(5, len(parsed)) if isinstance(parsed, dict) else 1
    evidence_bonus = min(8, evidence_signals)

    risk = min(100, max_risk + diversity_bonus + technique_bonus + critical_bonus + evidence_bonus)
    severity = "CRITICAL" if risk >= 90 else "HIGH" if risk >= 75 else "MEDIUM" if risk >= 50 else "LOW"
    confidence = min(99, avg_confidence + min(10, max(0, len(threats) - 1) * 4) + min(6, evidence_signals))

    return IncidentSummary(
        incident_id=incident_id,
        risk_score=risk,
        severity=severity,
        confidence=confidence,
        alert_count=len(rows),
        unique_threats=len(threats),
        unique_techniques=len(techniques),
        critical_alerts=critical,
        sources=sources,
        threats=threats,
        techniques=techniques,
        evidence_signals=evidence_signals,
        recommendations=recommendations_for(threats),
    )


_RECOMMENDATIONS = {
    "PORT_SCAN": (
        "Validate whether the source host is authorized to perform discovery.",
        "Review exposed services and restrict unnecessary inbound access.",
        "If unauthorized, isolate or block the source at an appropriate network control point.",
    ),
    "UDP_PORT_SCAN": (
        "Validate the source against approved discovery/scanning activity.",
        "Review exposed UDP services and firewall rules.",
        "Preserve packet evidence before containment if incident response is required.",
    ),
    "ICMP_SWEEP": (
        "Determine whether the source is an approved monitoring or discovery host.",
        "Review ICMP policy and unexpected east-west reachability.",
        "Correlate with subsequent service probes from the same source.",
    ),
    "SYN_FLOOD_PATTERN": (
        "Check the destination service for saturation or connection exhaustion.",
        "Correlate with connection failures and upstream network telemetry.",
        "Apply rate limiting or upstream filtering only after validating the event.",
    ),
    "BEHAVIORAL_TRAFFIC_ANOMALY": (
        "Compare the event with expected host workload or maintenance activity.",
        "Inspect the source host for newly introduced processes or scheduled jobs.",
        "Correlate DNS, connection and authentication telemetry before containment.",
    ),
}

_DEFAULT_RECOMMENDATIONS = (
    "Validate the alert against expected host and network activity.",
    "Review correlated telemetry and preserve relevant evidence.",
    "Escalate or contain only after confirming the activity is unauthorized.",
)


def recommendations_for(threats: Iterable[str]) -> tuple[str, ...]:
    """Return deterministic, defensive analyst guidance for observed threats."""
    selected = []
    seen = set()
    for threat in threats:
        for action in _RECOMMENDATIONS.get(str(threat), _DEFAULT_RECOMMENDATIONS):
            if action not in seen:
                seen.add(action)
                selected.append(action)
    return tuple(selected[:6])
