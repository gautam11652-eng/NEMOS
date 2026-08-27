# Changelog

## 3.2.8

- Added a small in-process dashboard snapshot cache keyed by the telemetry revision/ETag, avoiding repeated SQLite reads for unchanged dashboard state.
- Added composite alert indexes for incident-oriented dashboard/API queries.
- Fixed legacy-database migration ordering so indexes referencing additive alert columns are created only after those columns exist.
- Preserved bounded dashboard caching and ETag semantics; no live API data is persisted in the cache beyond the current process.

## 3.2.7

- Optimized SQLite retention maintenance to avoid full-table telemetry and host-stat recounts after every prune.
- Retention now applies incremental telemetry/host deltas and repairs only hosts whose risk/latest-alert fields may have changed.
- Batched host-stat upserts with `executemany()` to reduce SQLite statement overhead inside writer batches.
- Added regression coverage for retained host risk/latest-alert correctness.


## 3.2.6

- Included capture state in dashboard ETags so sensor failures/recovery and packet-capture counters are visible even when SQLite telemetry is unchanged.
- Hardened the SQLite writer lifecycle so unexpected worker exits no longer leave submissions accepted or make shutdown hang; the writer can be restarted cleanly.
- Corrected the dashboard color-scheme metadata to match the intentionally clean light workspace.

## 3.2.5

- Fixed Linux systemd packet capture by allowing the AF_NETLINK and AF_PACKET address families required by Scapy.
- Made the dashboard report an unset capture interface as `default` instead of incorrectly implying that every interface is being captured.
- Fixed the Kali verification script to check the actual lowercase `nemos/static/app.js` path.
- Standardized the manual-install default database filename to `data/nemos.db`.

## 3.2.4

- Fixed the dashboard KPI refresh crash caused by a missing UDP DOM element.
- Removed CSP-incompatible inline risk-ring styling and replaced it with SVG progress rendering.
- Added a clipboard fallback for non-secure dashboard contexts.
- Made sidebar navigation highlight the section currently being viewed.
- Added deterministic host ordering for equal-risk hosts.
- Bounded incident evidence in SQL instead of loading unbounded incident rows into memory.
- Added accurate host top-protocol telemetry to host investigations.
- Added dashboard asset/syntax regression tests.

##  

- Fixed stale uppercase `NEMOS.*` imports left in the test suite after the package rename to lowercase `nemos`.
- Added package-import regression coverage so future renames cannot silently break the test suite.

- Hardened packet-capture lifecycle with explicit runtime status and a finite Scapy sniff timeout so idle captures stop deterministically.
- Fixed production server shutdown by managing the Waitress server object explicitly.
- Added protected `/api/status` and capture state to dashboard responses.
- Dashboard now distinguishes healthy capture, missing `CAP_NET_RAW`, capture errors, disabled capture, and startup state instead of displaying all-zero telemetry as if the sensor were healthy.
- Reduced systemd privileges to `CAP_NET_RAW` only.
- Removed the Flask development-server fallback from `main.py`; deployment now requires the pinned Waitress dependency.
- Added regression coverage for capture state and runtime status.


## 3.2.2

- Added conditional dashboard responses with ETags to avoid retransmitting unchanged telemetry.
- Dashboard polling now pauses while the browser tab is hidden and uses request timeouts.
- Added regression coverage for conditional dashboard requests.
- Preserved batched SQLite writes and bounded queue/backpressure behavior.

## 3.2.1 - Runtime hardening

- Fixed `DetectionConfig.from_env()` startup crash caused by `dataclass(slots=True)` member descriptors.
- Bounded detector cooldown state to prevent attacker-controlled source churn from causing unbounded memory growth.
- Preserved the pre-update behavioral baseline in anomaly evidence.
- Hardened non-finite environment float handling.
- Reduced `/api/incidents` N+1 database queries to a bounded batched query.
- Added safe zero-state handling for telemetry counters.
- Hardened SQLite writer startup failure handling and exposed writer thread health in protected metrics.
- Made packet-capture lifecycle idempotent.
- Added regression coverage for the runtime startup and memory-bound issues.

## 3.2.1 — Final Validation & Release Engineering

- Centralized the application version in `nemos/version.py`.
- Synchronized package metadata, API health reporting, tests and documentation to 3.2.1.
- Added a final offline detection validation workflow using RFC 5737 documentation addresses only.
- Added release validation documentation and clean-source packaging checks.
- Kept live Flask/Scapy integration explicitly marked as a target-environment validation step.

## 3.1.0 — SIH Validation & Release Polish

- Added offline synthetic detection validation using RFC 5737 documentation addresses.
- Added SIH demo plan, five-minute demo script, and presentation outline.
- Synchronized package/API/test version metadata to 3.1.0.
- Corrected stale API version expectation in the integration test.
- Added release notes and a documented validation workflow.

## 3.0.0

- Added GitHub Actions CI across supported Python versions.
- Added dependency vulnerability auditing with pip-audit.
- Added reproducible package-build workflow.
- Added hardened systemd service template with least-privilege capabilities for packet capture.
- Added release checklist and local security-audit script.
- Added Makefile developer commands.
- Bumped application/package version to 3.0.0.

## 2.9.1 — Security & Reliability Audit
- Added Flask trusted-host validation with explicit trusted-host configuration for wildcard remote binds.
- Added stricter API packet validation for boolean ports and oversized timestamps.
- Expanded CSP with `base-uri`, `object-src`, `frame-ancestors`, and `form-action` restrictions.
- Added traffic destination/source-destination indexes and alert source/severity indexing.
- Refused remote startup when Waitress is unavailable instead of falling back to Flask's development server.
- Added explicit process exit status handling.
- Updated remote deployment documentation and environment example.

## 2.9.0 — Adversarial Reliability & Backpressure
- Added priority-aware bounded SQLite backpressure with a reserved queue region for alerts.
- Traffic can be shed under sustained overload instead of allowing unbounded memory growth or blocking packet capture indefinitely.
- Alerts receive a short blocking window and reserved capacity so traffic bursts cannot starve security findings.
- Added writer operational metrics: queue depth, high-water mark, dropped traffic/alerts, write errors, and completed batches.
- Added authenticated `/api/metrics` for runtime writer health.
- Hardened shutdown draining so all queued work is processed before the writer exits.
- Added deterministic saturation/priority tests and a 50,000-event storage stress benchmark.

## 2.9.0 — Investigation Workflow

- Added host investigation endpoint and UI.
- Added alert detail endpoint.
- Added incident defensive guidance and evidence-focused investigation view.
- Added alert acknowledgement controls to the incident workflow.
- Added bounded host/incident investigation data.

## 2.9.0
- Added deterministic adaptive behavioral profiling with EMA mean/variance across packet rate, byte rate, destination diversity, and port diversity.
- Behavioral sampling is cadence-limited to prevent packet-by-packet baseline drift.
- Behavioral alerts include current values, baseline values, sigma deviations, and model metadata.


## 2.5.0 - Detection Engine v3

- Added evidence-driven UDP port-scan and ICMP sweep detections.
- Added explicit TCP SYN scan evidence and scan classification.
- Improved confidence calibration and minimum-confidence gating.
- Kept behavioural anomaly detection explainable and removed misleading ATT&CK mapping from generic anomalies.
- Added bounded ARP state eviction.
- Expanded detector tests for new reconnaissance signals.


## 2.9.0 - SOC Intelligence Layer
- Added explainable host-risk summaries and `/api/hosts`.
- Added bounded incident investigation endpoint `/api/incidents/<incident_id>`.
- Added host-risk panel to the SOC dashboard.
- Kept host risk as a triage score, not an automated attribution verdict.

## 2.1.0
- Added O(1) dashboard/stat counters with automatic migration/backfill for existing databases.
- Protected read-only API telemetry when an API token is configured.
- Added dashboard token entry with local-only browser storage.
- Added strict IP, port, protocol and packet-size validation for packet ingestion.
- Hardened SQLite writer lifecycle, shutdown draining, lock retries and error accounting.
- Added safer environment parsing and packaged `main.py` as the console entry point.
- Fixed the service-connection ATT&CK mapping to network service scanning (`T1046`).
- Expanded lifecycle, authentication, validation and configuration tests.


## 2.0.0
- Rebuilt architecture around one lifecycle entry point.
- Added real Scapy packet capture.
- Added bounded multi-signal detection engine.
- Added MITRE ATT&CK technique references.
- Added batched SQLite WAL writer.
- Added consolidated dashboard endpoint and 3-second polling.
- Added request validation, API token protection, security headers and loopback-safe defaults.
- Added SOC-style responsive dashboard.
- Added tests, packaging metadata, security policy and contributor guidance.
- Removed virtual environment, runtime databases, backups and caches from source distribution.

## 2.2.0 - Detection Engine v2

- Added source-level incident correlation with stable incident IDs.
- Added explainable behavioural traffic-baseline detection with bounded per-source state.
- Expanded evidence attached to network-scan and flood detections.
- Added `/api/incidents` and incident data to `/api/dashboard`.
- Added incident-aware SOC dashboard views.
- Added `incident_id` storage migration and index.
- Reworked telemetry statistics to use O(1) incremental updates during normal batches; full recounts occur only when retention pruning changes stored rows.
- Added retention/statistics regression tests.

## 2.6.0 — Incident Intelligence

- Added deterministic, explainable incident-level risk summarization.
- Added incident confidence, severity, threat/technique diversity and evidence metrics.
- `/api/incidents` now returns enriched incident triage summaries.
- `/api/incidents/<incident_id>` now returns an incident summary alongside alert evidence.
- Incident scoring is bounded to 0–100 and is explicitly a triage priority, not a probability of compromise.

## 2.9.0 — Adaptive Behavioural Intelligence
- Added deterministic EW mean/variance profiling for packet rate, byte rate, destination diversity, and port diversity.
- Added cadence-limited baseline sampling to reduce baseline drift during bursts.
- Added explainable sigma-deviation evidence to behavioural alerts.
- Added bounded profile storage and configurable behavioural settings.
