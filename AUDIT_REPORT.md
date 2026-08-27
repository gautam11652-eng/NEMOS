# NEMOS Security & Runtime Audit

This release was reviewed from the source distribution before packaging.

## Fixed findings

- **Startup blocker:** `DetectionConfig.from_env()` read slotted dataclass class attributes such as `cls.baseline_alpha`. With `slots=True`, those names are member descriptors rather than float defaults, causing `TypeError: '<' not supported between instances of 'member_descriptor' and 'float'` during `python main.py`.
- **Unbounded detector state:** cooldown bookkeeping could grow with attacker-controlled source addresses even though packet/event state was bounded. Cooldown state is now bounded and evicts the oldest entries.
- **Misleading behavioral evidence:** the profiler returned a baseline after updating it with the current observation. Evidence now records the pre-update baseline used for the comparison.
- **Non-finite configuration values:** NaN/Infinity behavior settings are rejected in favor of defaults.
- **API N+1 query pattern:** incident listing now batches evidence retrieval instead of querying once per incident.
- **Writer failure handling:** a database-open failure now marks the writer unavailable instead of leaving callers believing it is accepting work forever.
- **Capture lifecycle:** repeated `start()` calls are idempotent; capture now exposes explicit state/counters and uses a finite Scapy sniff timeout so idle capture can stop deterministically.
- **Telemetry zero state:** stats endpoints tolerate a missing cached counter row and return a safe zero state instead of raising a server error.
- **Browser token persistence:** dashboard API tokens now use `sessionStorage` rather than persistent `localStorage`, reducing credential lifetime on shared browsers.
- **HTTP shutdown:** the production entry point now owns the Waitress server object and closes it on SIGINT/SIGTERM before joining capture/storage resources.
- **Privilege boundary:** the supplied systemd unit grants only `CAP_NET_RAW` for packet capture and keeps the application process unprivileged.
- **Telemetry truthfulness:** the dashboard now distinguishes capture-disabled, capture-starting, capture-running, permission-denied, and capture-error states instead of presenting all-zero telemetry as a healthy sensor.
- **Deployment fallback:** the production entry point no longer silently falls back to Flask's development server; Waitress is required.

## Verification performed

- Python bytecode compilation: passed.
- Runtime regression tests: passed.
- Existing dependency-independent test suites plus the new lifecycle regression: **34 passed** in the offline audit environment; 2 package-namespace import checks also passed using a minimal Flask import stub.
- The source tree currently contains 49 test functions, including 13 Flask API integration tests that require the pinned runtime dependencies. Those 13 could not be executed in this isolated audit environment because package installation is unavailable.
- Runtime dependencies remain pinned in `requirements.txt`; run `pip-audit` in the target Kali environment before deployment because this audit container cannot access the package index.

## Verification boundary

The audit environment used for this source review does not have Flask/Scapy/Waitress installed and cannot reach PyPI, so a fresh end-to-end HTTP/capture execution could not be performed here. The code was compiled and the dependency-independent runtime paths were exercised. On Kali, install the pinned requirements and run the full suite before deployment:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
python main.py
```

No software audit can honestly guarantee zero future vulnerabilities. Keep the pinned dependencies updated and rerun `pip-audit` before public releases.
