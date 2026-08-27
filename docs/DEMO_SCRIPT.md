# Five-minute NEMOS demonstration script

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
