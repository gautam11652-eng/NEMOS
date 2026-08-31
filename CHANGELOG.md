# Changelog

## 4.1.0

Detection coverage, a rebuilt interface, and two defects found by testing the
running system rather than the unit suite.

### Added

- **Seventeen new detections**, all derived from metadata NEMOS already
  captures. Beaconing (periodicity by coefficient of variation of contact
  intervals), lateral movement, credential brute force and password spraying,
  data exfiltration, stealth TCP flag scans, DNS and ICMP tunneling, endpoint
  denial of service, reflection amplification, ingress tool transfer,
  crypto-mining and Tor port heuristics, and non-standard port traffic.
  Detection rules: 10 -> 27.
- **ATT&CK coverage 5 -> 26 techniques**, spanning seven tactics where it
  previously spanned two. Coverage was expanded by adding detections, never by
  adding catalog entries: a test asserts the catalog contains no technique the
  detector cannot emit.
- **Exfiltration over an established C2 channel** (T1041) is distinguished from
  generic exfiltration (T1048) by correlation — bulk transfer to a host the
  same source was already beaconing to.
- **Rebuilt dashboard**: six routed views, an intrusion-progression view
  placing findings on the ATT&CK tactic they evidence, an evidence drawer, a
  beacon periodicity plot, filtering and pagination throughout, a command
  palette, and light/dark themes.
- **`tools/benchmark.py`**, a reproducible capture-path benchmark. Every
  performance number in the documentation now comes from it.

### Fixed

- **The dashboard could never authenticate.** The API reads `X-NEMOS-Token`;
  the rewritten script sent `Authorization: Bearer`. Against a token-protected
  sensor every request returned 401 and saving a token changed nothing. The
  dashboard now sends the documented header, and the API additionally accepts
  a standard bearer token because that is what scripts reach for by default.
- **Detection scanned the window once per rule.** Cost per packet was rules
  times window size: 130 -> 853 us/packet as rules were added. Detection runs
  inline on the capture thread, so this was dropped traffic. Every windowed
  statistic is now derived in one traversal; address parsing and TCP flag
  classification are memoised with bounded caches. 853 -> 256 us/packet on the
  same workload.
- `[hidden]` was overridden by component display rules, so every dashboard
  view, the drawer and the palette painted simultaneously.
- The favicon was a `data:` URI, which the page's own Content-Security-Policy
  refused; it is now a served file, which also fixes a 404 on every load.
- The dashboard fetched `/api/attack`, which is not a route.
- Port scanning from an external source is now reported as Reconnaissance
  (T1595) rather than Discovery (T1046); host sweeps as Remote System Discovery
  (T1018) rather than Network Service Discovery.

- **Telegram counted an undelivered message as sent.** The Bot API reports its
  outcome in the body, and can answer HTTP 200 with `{"ok": false}`. Only the
  status line was checked, so those were recorded as delivered: a silent failure
  in the alerting path. The response body is now authoritative. The test double
  had defaulted to an empty body, which the real API never returns -- a fake
  more permissive than the service it stood in for, which is why this survived.
- **Capture reported "starting" forever on a quiet link.** State only advanced
  to "running" when the first packet arrived, so a correctly bound sensor on an
  idle interface was indistinguishable from one that never came up. It now flips
  on a successful socket bind via Scapy's started_callback.
- **A dead capture thread reported no error at all.** A BaseException such as a
  native panic escapes `except Exception`, leaving the status stuck at
  "starting" with `error: null`. Status is now reconciled against whether the
  thread is alive, and reports "failed" with an actionable message.

### Changed

- **Corrected a published performance claim.** 4.0.0 reported 189,356
  packets/sec. That figure was measured on a benchmark whose event windows
  stayed nearly empty and did not represent a busy network; it should not have
  been published as a single headline number. Measured range is now 5,059
  packets/sec (50 sources, windows full) to 38,319 (5,000 sources), and the
  README documents why the slowest figure is the one to plan against.
- Per-packet cost remains linear in window size. This predates 4.1.0 and is
  documented as a known limitation rather than left implicit.

### Verified

- **Live packet capture now works and is tested.** Capture binds a real socket
  on loopback, and the TCP, UDP, DNS and ICMP parse paths were all exercised by
  self-generated traffic (490 packets through the full sensor: capture ->
  detector -> storage -> API -> dashboard), producing real findings. Covered by
  tests/test_capture_live.py, which skips where raw capture is unavailable.
- **Telegram transport verified against the live Bot API.** A request to
  api.telegram.org completed the full DNS, TLS and HTTP round trip and returned
  a real 401, which NEMOS parsed, redacted and diagnosed correctly.

### Known limitations

- Telegram delivery with a **valid** token has still not been performed: no
  credentials exist in the development environment, so no message has arrived in
  a real chat. Everything up to that hop is now verified, and
  `tools/verify_telegram.py` performs the check in one command.

## 4.0.0

Major release: NEMOS gains a genuine machine-learning detection layer alongside
the existing deterministic rules, built around an explicit unidirectional flow
model. The existing detector is unchanged in behaviour and remains the
authoritative layer.

### Added

- **Unidirectional flow aggregation** (`nemos/flows.py`). The five-tuple is used
  exactly as observed with no canonicalisation, so A->B and B->A are separate
  records that are never merged. A one-way tap is a first-class deployment, and
  no feature requires a response packet. `reverse_of()` correlates the opposite
  direction without merging either side.
- **Feature engineering** (`nemos/features.py`). 24 features per source per
  window: volume, rates, per-flow statistics, fan-out counts, Shannon entropy
  over destinations and ports, packet-size statistics, TCP flag ratios and
  protocol ratios. Free of any ML dependency so it is testable and reusable on
  its own. Ordered and schema-versioned.
- **Unsupervised ML anomaly detection** (`nemos/ml.py`). An Isolation Forest
  from scikit-learn, trained locally on the operator's own benign traffic. No
  labelled attack data, no cloud service and no internet access are required.
  Reproducible via a fixed seed; model, calibration and provenance metadata are
  persisted atomically.
- **Explainability.** The model exposes no per-feature attribution, so NEMOS
  reports which features are furthest from their training mean in standard
  deviations. Every assessment carries those alongside the score.
- **Hybrid risk fusion** (`nemos/fusion.py`). Deterministic rules set the risk
  floor and are the only source of an ATT&CK technique; statistical layers may
  raise a score but never lower it, and alone cannot reach CRITICAL. Every
  result carries the arithmetic that produced it.
- **Explicit baseline states**: `NO_BASELINE`, `NORMAL`, `DEVIATING`,
  `HIGHLY_DEVIATING`. A host without enough history is `NO_BASELINE` -- never
  "normal" and never "anomalous".
- **Windowed analysis engine** (`nemos/analysis.py`) on its own thread. The
  capture path does one dictionary operation per packet; expiry, feature
  extraction, batched inference and fusion happen off it.
- **Model lifecycle CLI** (`tools/train_model.py`): train from captured traffic
  or synthetic data, dry-run inspection, JSON output. Training is out-of-band by
  design -- a sensor that retrained itself on live traffic would learn to accept
  an intrusion in progress.
- **Controlled demonstration** (`tools/demo.py`, `tools/scenarios.py`) across
  nine traffic shapes, generated in memory using RFC 5737 documentation
  addresses. Nothing is transmitted and no host is contacted.
- **Optional LLM analyst** (`nemos/analyst.py`). Explains findings the other
  layers already made; performs no detection and is never in the packet path.
  Responses are verified against the evidence bundle and discarded if they
  reference an IP address or technique that is not in it. Hosted provider
  endpoints cannot be redirected by configuration; `ollama` must be loopback.
- **API**: `/api/flows`, `/api/analysis`, `/api/anomalies`, `/api/windows`,
  `/api/baselines`, `/api/baselines/<ip>`, `/api/analyst`, and
  `POST /api/analyst/ask`, which takes a target and never caller-supplied
  evidence so it cannot be used as an open LLM proxy.
- **Dashboard**: a ML Detection section showing model state and provenance,
  per-assessment anomaly score, baseline state, the hybrid arithmetic and the
  contributing features. A test pins that every field maps to a real backend
  value and forbids overstated wording.
- Flows are persisted through the existing batched writer as a third item kind,
  treated as telemetry for backpressure so they are dropped before findings.

### Fixed

- **Flow-table eviction was O(n) per packet.** It scanned for the oldest entry,
  so the bound that exists to survive a spoofing flood became the bottleneck
  exactly when full. Now an `OrderedDict` with O(1) LRU, matching the detector
  and profiler. A 200,000-packet benchmark did not finish before this fix; it
  now sustains a high ingest rate. A test pins the complexity.
  (Correction, 4.1.0: the figure originally published here was measured on a
  benchmark that kept event windows nearly empty and did not represent a busy
  network. See tools/benchmark.py and the Performance section of the README.)
- **The anomaly score anchored on the training minimum**, a single sample, so
  one unusual training window set the whole scale. Measured here the minimum was
  -0.255 against a 5th percentile of -0.030, stretching the band until a
  259-port SYN scan scored 65. The score now uses robust deviation units
  anchored on the median and 5th percentile, with bands from measured
  separation. Scenario scores moved from 64-69 to 84-100 with normal traffic
  still producing no finding.
- **The aggregation window was not part of the model contract.** Counts and
  rates scale with it, so a model fitted on 10s windows applied to 2s windows
  scored a distribution it had never seen. Training now records the window,
  mixed-window corpora are refused, and loading refuses a mismatch with a
  message naming both fixes.
- **Training accepted a degenerate corpus.** The minimum sample count counted
  rows, so many copies of one window passed while teaching the forest nothing --
  and a scan then scored *lower* than normal traffic. A distinct-sample minimum
  now applies, and constant features are reported.
- `ThreatDetector.process()` and `observe_arp()` accept an optional `now`.
  They previously always read the monotonic clock, so replaying an hour of
  traffic in a second placed every event in one window and manufactured
  findings. Live capture is unchanged.
- `/api/packet` now also feeds the windowed flow pipeline, so synthetic traffic
  exercises flow aggregation, features and ML rather than only reaching storage.
  It deliberately does not invoke the deterministic detector, whose per-source
  state is owned by the capture thread.

### Changed

- Version 3.3.0 -> 4.0.0.
- `scikit-learn` and `joblib` are runtime dependencies, but every import is
  guarded: without them NEMOS runs deterministic rules plus the statistical
  baseline exactly as before, and reports why ML is unavailable.
- Documentation rewritten to describe the three layers separately and to state
  plainly what each can and cannot evidence.

### Testing

278 -> 338 tests. Measured on this machine: feature extraction 52.76 ms for 20,000 flows into 50
source vectors, batched inference 15.08 ms for 50 vectors (0.302 ms per
source-window).

**Real Telegram delivery was not tested**: no credentials were present in this
environment. The delivery path is covered by tests using a recording transport,
which verify request shape, retry, redaction, suppression and non-blocking
behaviour, but no message was sent to Telegram.

## 3.3.0

### Added
- **Outbound alert delivery.** Telegram and generic-webhook channels now actually
  send findings. Previously the Telegram integration was documented and shown in
  the dashboard but had no delivery code path at all: `/api/telegram` only
  reported whether the credentials were set, and no alert was ever sent anywhere.
  Delivery runs on a worker thread and never blocks packet capture; storage
  happens first, so an unreachable channel cannot cost a recorded detection.
- Severity floor, per-finding cooldown and a global token-bucket rate limit, so a
  port scan cannot turn the sensor into a message flood. Suppressed alerts remain
  recorded and every suppression is counted.
- `.env` loading. The README and `.env.example` had instructed users to create a
  `.env` file, but nothing in the codebase ever read one, so file-based settings
  were silently ignored. Real environment variables still take precedence.
- `GET /api/notifications` and delivery metrics on `/api/status` and
  `/api/metrics`, so operators can tell "credentials present" from "alerts are
  actually arriving".
- Filtering on `GET /api/alerts`: `severity` (repeatable), `source`, `threat`,
  `technique`, `acknowledged` and `since`, all bound as parameters.
- Ruff lint configuration and a CI lint job; CI now also verifies that built
  artifacts carry the version from `nemos/version.py`.

### Fixed
- **Duplicate writes on shutdown.** The SQLite writer's sentinel-drain path
  flushed the final partial batch and then fell through to a `finally` clause
  that flushed the same still-populated list again. Any traffic and alerts
  pending at shutdown were written twice, and the cached telemetry counters were
  incremented twice with them. This hit every clean shutdown where the last
  batch had not already been flushed by the timeout path -- the common case for
  a busy sensor being stopped. Covered by a regression test.
- The dashboard's writer-queue health tile read `queue_size` from the dashboard
  payload, but the metric is named `queue_depth` and `/api/dashboard` never
  returned writer metrics at all, so the tile was permanently blank. It now reads
  live depth and capacity from `/api/status`.
- `TimeoutError` raised during writer shutdown lost its originating exception.

### Changed
- Packaging version is single-sourced from `nemos/version.py` via
  `dynamic = ["version"]`; it was previously duplicated by hand in
  `pyproject.toml` and could drift from the version `/api/health` reports.
- `/api/alerts` and `/api/traffic` select explicit columns instead of `SELECT *`.
- Telegram alert text is sent with no Markdown/HTML parse mode, so alert content
  cannot break rendering or inject formatting.
- Webhook URLs must be HTTPS unless loopback, and HTTP redirects are refused
  rather than followed.

### Documentation
- **Corrected an overstatement risk.** The README's "Detection Engine v3"
  heading described the behavioural baseline in terms that could be read as
  machine learning. It is an exponentially weighted mean/variance model with an
  explicit sigma threshold — a transparent statistical baseline, not a trained
  one. The README now says so directly in a "What NEMOS is not" section, and
  `CONTRIBUTING.md` makes not describing it as AI or ML a contribution rule.
  (`detector.py` already stated this correctly in a comment; only the docs
  overstated.)
- Resolved a version-label contradiction: the README called the detector
  "Detection Engine v3" while `docs/ARCHITECTURE.md` called the same component
  "v2". Both now describe it without a version label.
- Fixed the documented test command. `README.md`, `CONTRIBUTING.md` and
  `docs/RELEASE.md` told users to run `python -m unittest discover`, but the
  project uses pytest — which is what CI, the Makefile and `pyproject.toml`
  configure.
- Corrected the systemd instructions. The README implied a service could be set
  up by copying two files; the packaged unit expects a `nemos` account, a venv
  at `/opt/nemos` and `/var/lib/nemos`, all of which `install.sh` creates.
- Rewrote the README: removed a duplicated introduction, moved the License
  section out of the middle of the document, added status badges, an
  architecture diagram, full configuration tables, an API table and an explicit
  Limitations section.
- Rewrote `docs/ARCHITECTURE.md`, which predated `notify.py` and `env.py`, and
  `docs/RELEASE.md`, which contained stale release notes rather than a process.
- Expanded `CONTRIBUTING.md` and `SECURITY.md`; added `CODE_OF_CONDUCT.md`,
  issue and pull-request templates, `dependabot.yml` and `.editorconfig`.

### Removed
- `backup_before_final_ui/` and four committed `*.pre_polish` files.
- `FINAL_AUDIT.md`, `TEST_REPORT.md` and `TEST_REPORT_LOCAL.md`, consolidated
  into a single current `AUDIT_REPORT.md`.

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

## Dashboard polish — 2026-08-30

- Replaced the broken Risk Distribution board with a deterministic Security Posture panel.
- Reworked the dashboard into a restrained dark SOC interface with clearer hierarchy and denser operational information.
- Expanded the MITRE ATT&CK section to show the complete conservative NEMOS catalog, observed counts, tactics, descriptions, and unmapped behavioral signals.
- Added Telegram configuration/status visibility without exposing the bot token.
- Added a compact creator panel for Gautam with the NEMOS GitHub repository and contact email.
- Corrected NEMOS branding to `Network Exposure Monitoring & Operations System` throughout the dashboard.
- Preserved existing incident, host, network, acknowledgement, evidence-export, and polling workflows.
