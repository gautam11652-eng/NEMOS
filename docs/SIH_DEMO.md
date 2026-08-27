# NEMOS — SIH Demo Plan

## Objective

Demonstrate that NEMOS can turn network telemetry into an explainable,
correlated security incident without requiring a cloud service or an external
AI API.

## Safe demonstration

Use the offline validation harness:

```bash
python tools/validate_detection.py
```

It generates **synthetic RFC 5737 documentation-address telemetry** in memory.
It does not transmit packets, scan a host, or interact with a third-party
network.

Expected flow:

```text
Synthetic telemetry
      ↓
Packet/event normalization
      ↓
Evidence-backed detector
      ↓
Confidence + risk score
      ↓
Incident correlation
      ↓
MITRE ATT&CK mapping
      ↓
SOC investigation view
```

## Live Kali demonstration

For an authorized lab network only, start NEMOS with packet capture and
show normal traffic first. Then use a pre-approved test dataset or controlled
lab traffic. Do not demonstrate against systems you do not own or have
permission to test.

## Judge narrative

1. **Problem:** smaller organizations often lack an affordable, local SOC view.
2. **Approach:** combine packet telemetry, deterministic rules, behavioral
   baselines and incident correlation.
3. **Explainability:** every alert carries evidence, confidence, risk and an
   ATT&CK mapping only when the observed behavior supports it.
4. **Resilience:** bounded queues and state prevent traffic floods from causing
   unbounded memory growth.
5. **Privacy:** no outbound telemetry is required by default; the platform can
   operate entirely locally.
6. **Open source:** reproducible packaging, tests, CI and security guidance are
   included.

## What not to claim

Do not claim that a risk score is a probability of compromise, that the system
has zero false positives, or that it can detect every attack. Present the score
as analyst triage priority and show the evidence behind each finding.
