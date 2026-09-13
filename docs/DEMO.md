# Demo and presentation notes

Material for showing NEMOS live. Kept together because all three were
separate one-page files that said overlapping things.

---

## Five-minute NEMOS demonstration script

### 0:00–0:45 — Problem

"Traditional enterprise SOC tooling can be expensive and complex. NEMOS
is designed as a local, open-source defensive monitoring platform for teams that
need visibility without sending their telemetry to a cloud service."

### 0:45–1:30 — Architecture

Show:

```text
Capture → Parser → Detection → Behavioral Baseline
       → Correlation → SQLite → API → SOC UI
```

Mention bounded queues, WAL-backed SQLite and explainable detections.

### 1:30–2:30 — Normal operation

Show the live sensor, packet rate, protocol distribution and host-risk panel.

### 2:30–3:45 — Controlled detection

Run the safe offline validation harness or use an authorized lab dataset.
Show the generated finding, evidence, confidence, risk and ATT&CK mapping.

For network-service discovery, NEMOS uses T1046 only when the evidence
supports it. MITRE describes T1046 as Network Service Discovery and documents
behavioral detection approaches based on rapid connections to multiple services
or hosts. See the official ATT&CK reference before the presentation.

### 3:45–4:30 — Investigation

Open the incident and show:

- correlated alerts
- timeline
- evidence
- affected host
- techniques
- defensive recommendations

### 4:30–5:00 — Engineering

Highlight:

- bounded resource usage
- authentication and trusted-host controls
- SQLite batching/WAL
- automated tests
- CI/security audit
- local-first operation

Finish with the project's open-source roadmap.

---

## NEMOS — SIH Demo Plan

### Objective

Demonstrate that NEMOS can turn network telemetry into an explainable,
correlated security incident without requiring a cloud service or an external
AI API.

### Safe demonstration

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

### Live Kali demonstration

For an authorized lab network only, start NEMOS with packet capture and
show normal traffic first. Then use a pre-approved test dataset or controlled
lab traffic. Do not demonstrate against systems you do not own or have
permission to test.

### Judge narrative

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

### What not to claim

Do not claim that a risk score is a probability of compromise, that the system
has zero false positives, or that it can detect every attack. Present the score
as analyst triage priority and show the evidence behind each finding.

---

## SIH presentation outline

1. **Title** — NEMOS: Local, Explainable Network Defense
2. **Problem** — visibility and SOC tooling are difficult for smaller teams
3. **Why existing approaches fall short** — cost, complexity, cloud dependence
4. **Solution** — local telemetry + behavioral detection + correlation
5. **Architecture** — capture through investigation
6. **Detection** — evidence, confidence, risk and ATT&CK mapping
7. **Resilience** — bounded memory, prioritized backpressure, SQLite batching
8. **UX** — SOC command center and investigation workflow
9. **Validation** — automated tests + safe controlled demonstration
10. **Impact** — deployable on modest Linux hardware, open source
11. **Roadmap** — richer protocol analytics, federation, optional threat-intel feeds
12. **Closing** — measurable, explainable and locally controlled defense
