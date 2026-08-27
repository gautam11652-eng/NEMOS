#!/usr/bin/env python3
"""Offline NEMOS validation harness using synthetic, non-network traffic.

This intentionally does not transmit packets or scan hosts. It exercises the
same detector with controlled TrafficEvent objects for demo/CI validation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow direct execution from the repository root (``python tools/validate_detection.py``).
# When Python executes a script, sys.path[0] is the tools directory rather than
# the project root, so the package would otherwise be invisible.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nemos.detector import DetectionConfig, ThreatDetector
from nemos.models import TrafficEvent


def event(source: str, destination: str, port: int, protocol: str = "TCP", flags: str = "S") -> TrafficEvent:
    return TrafficEvent(
        timestamp="2026-08-18T00:00:00+00:00",
        source=source,
        destination=destination,
        protocol=protocol,
        source_port=40000,
        destination_port=port,
        packet_size=80,
        flags=flags,
    )


def main() -> int:
    cfg = DetectionConfig(
        window=10,
        port_scan=6,
        udp_scan=6,
        icmp_sweep=6,
        fanout=10,
        cooldown=0,
        baseline_min_samples=3,
        baseline_min_events=6,
        min_confidence=50,
    )
    detector = ThreatDetector(cfg)
    source = "192.0.2.10"  # RFC 5737 documentation address; no packets are sent.

    alerts = []
    for port in (21, 22, 23, 25, 53, 80, 110, 143):
        alerts.extend(detector.process(event(source, "198.51.100.20", port), "TCP"))

    if not alerts:
        raise SystemExit("validation failed: expected a controlled scan-pattern detection")

    result = {
        "status": "PASS",
        "alert_count": len(alerts),
        "threats": sorted({a.threat for a in alerts}),
        "techniques": sorted({a.technique for a in alerts if a.technique}),
        "max_risk": max(a.risk_score for a in alerts),
        "max_confidence": max(a.confidence for a in alerts),
        "incident_ids": sorted({a.incident_id for a in alerts}),
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
