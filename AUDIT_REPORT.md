# NEMOS Security & Runtime Audit

This file records the security-relevant design decisions in NEMOS and the
verification that has actually been performed. It replaces the earlier
`FINAL_AUDIT.md`, `TEST_REPORT.md` and `TEST_REPORT_LOCAL.md`, which had drifted
into four overlapping point-in-time snapshots of the same review.

No audit can promise the absence of future vulnerabilities. Keep the pinned
dependencies current and re-run `pip-audit` before any release.

## Standing security properties

These are the invariants the code and test suite are written to protect. Each
one has at least one regression test.

### Network exposure
- Loopback bind by default. A non-loopback bind requires `NEMOS_API_TOKEN`, and
  a wildcard bind (`0.0.0.0`, `::`) additionally requires `NEMOS_TRUSTED_HOSTS`.
  Both are enforced in `load_settings`, at startup, not at first request.
- Every `/api/*` route except `/api/health` requires `X-NEMOS-Token` when a
  token is configured; comparison uses `hmac.compare_digest`.
- With no token configured, mutating requests still reject cross-site browser
  writes via `Sec-Fetch-Site` and `Origin`, so an unrelated page cannot drive a
  localhost sensor.
- CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`
  are set on every response; API responses are `no-store`.
- Request bodies are capped at 32 KB.

### Input handling
- Packet ingestion validates source/destination as real IP addresses, the
  protocol against an allow-list, and ports/sizes against their numeric ranges.
- Alert filters (`severity`, `source`, `threat`, `technique`, `acknowledged`,
  `since`) are validated against known sets or length caps and passed as bound
  parameters. No user-supplied value is interpolated into SQL text.
- Path parameters (`incident_id`, `host`) are character- and length-validated.

### Bounded state
Every map keyed by an attacker-influenceable value has an eviction bound,
because a spoofed source address must not be able to grow process memory:
per-source event buckets, behavioural profiles, ARP mappings, alert cooldowns,
incident correlation, and the notifier's delivery cooldown.

### Storage
- A single writer thread owns SQLite; WAL mode, busy timeout, and bounded retry
  on lock contention.
- The queue is bounded and reserves capacity for alerts, so a packet flood
  cannot starve security findings. Overflow is counted, never silently lost.
- Traffic and alert tables are pruned to configured retention limits, with
  cached counters and host summaries updated incrementally rather than by
  full-table scans.
- The database file is created `0600` inside a `0700` directory.

### Secrets
- The Telegram bot token appears in the request URL, so every error string and
  log line is redacted before it can escape (`notify.redact`).
- No endpoint returns a credential. `/api/telegram` and `/api/notifications`
  report only whether a credential is set, plus a masked chat-id tail.
- The `.env` loader logs variable *names* only, never values.
- Dashboard API tokens are held in `sessionStorage`, not `localStorage`.

### Outbound alert delivery
- Delivery never blocks packet capture: `submit` is non-blocking and all
  network I/O happens on a worker thread.
- Webhook URLs must be HTTPS unless the host is loopback, so alert bodies
  describing the monitored network are not sent in cleartext.
- HTTP redirects are refused rather than followed, so a redirect cannot
  downgrade the transport or retarget the payload.
- Severity floor, per-finding cooldown and a global token bucket bound outbound
  volume, so a scan cannot turn the sensor into an amplifier.
- Storage happens before delivery. An unreachable chat API never costs a
  recorded detection.

### Privilege boundary
The supplied systemd unit grants `CAP_NET_RAW` only and runs the application
unprivileged. The web application is never intended to run as root.

### Honest telemetry
The dashboard distinguishes capture-disabled, starting, running,
permission-denied and error states rather than presenting all-zero telemetry as
a healthy sensor. Delivery status likewise distinguishes "credentials present"
from "alerts are actually arriving".

## Detection integrity

Detections are deliberately conservative and evidence-backed:

- ATT&CK technique IDs are attached only where the observed network behaviour
  supports the mapping. A generic traffic anomaly is reported as an unmapped
  behavioural signal rather than being assigned a misleading technique.
- The behavioural baseline is an explicitly documented exponentially weighted
  mean/variance model, not a black-box ML claim. Every anomaly is explainable as
  a deviation from that source's own observed baseline, and the evidence records
  the pre-update baseline the comparison actually used.
- A zero-variance warm-up cannot produce an infinite z-score; per-feature noise
  floors keep a one-unit change from reading as hostile.
- A single noisy feature is not treated as an attack: the strongest deviation
  must be supported by an independent dimension unless it is extreme.

## Previously fixed findings

Retained for release history; all are covered by regression tests.

- `DetectionConfig.from_env()` read slotted dataclass member descriptors as
  float defaults, raising `TypeError` at startup.
- Cooldown bookkeeping could grow unbounded with attacker-controlled sources.
- The behavioural profiler reported a baseline it had already updated with the
  observation being judged.
- NaN/Infinity configuration values are rejected in favour of defaults.
- Incident listing issued one query per incident (N+1); it now batches.
- A database-open failure left callers believing the writer still accepted work.
- Repeated `capture.start()` calls are idempotent, and sniffing uses a finite
  timeout so idle capture stops deterministically.
- Stats endpoints tolerate a missing cached counter row instead of raising 500.
- The entry point owns the Waitress server and closes it on SIGINT/SIGTERM.
- The production entry point no longer falls back to Flask's dev server.
- The writer's shutdown path wrote the final partial batch twice, duplicating
  stored traffic and alerts and double-counting the cached telemetry stats.
- The dashboard's writer-queue tile read a metric key that was never sent, so it
  displayed nothing; it now reads live depth and capacity from `/api/status`.
- The documented `.env` workflow had no loader behind it, so `TELEGRAM_*` and
  other file-based settings were silently ignored.
- Telegram alerting was documented and surfaced in the UI but had no delivery
  code path at all; findings were never actually sent anywhere.

## Verification

Run in the target environment:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q main.py nemos tests
python -m pip_audit -r requirements.txt
ruff check .
```

CI runs the suite on Python 3.10–3.13, plus lint, dependency audit and a
package build.

### Scope limits

Two areas cannot be covered by the unit suite and need a real Linux host:

- **Live packet capture.** Tests exercise the parse and lifecycle paths with
  synthetic packets; they do not put an interface in promiscuous mode.
- **Outbound delivery over the network.** Tests inject a recording transport to
  verify request shape, retry, redaction, suppression and non-blocking
  behaviour. They deliberately never contact `api.telegram.org`. Confirm real
  delivery once against your own bot before relying on it.
