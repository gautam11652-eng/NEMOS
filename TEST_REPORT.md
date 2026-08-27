# NEMOS Test Report

## Environment
- Python: 3.13.x in the isolated build environment.
- Node.js: 22.x.
- Flask/Scapy/Waitress are not installed here and outbound package installation is unavailable.

## Executed successfully
- 34 dependency-independent tests: **PASS**
- Python compilation (`compileall`): **PASS**
- JavaScript syntax check (`node --check`): **PASS**
- Offline synthetic detection validation: **PASS**
  - 6 detections
  - T1046
  - max risk 89
  - max confidence 99
  - 1 correlated incident
- SQLite backpressure/stress validation from the previous release pass: **PASS**
- Static dangerous-code scan: **PASS**
- Clean source-package audit: **PASS**
- Local wheel build (`pip wheel --no-deps --no-build-isolation`): **PASS**
- Lowercase package import regression checks: **PASS** (2 checks using a minimal Flask import stub; full API execution still requires Flask)
- Total test functions in the source tree: 49 (13 API integration tests require Flask/Waitress runtime dependencies)

## Not executed here
- Flask/Waitress API integration tests
- Live Scapy packet capture
- Linux systemd capability/service validation
- Network-interface-specific testing on Kali

These require the runtime dependencies and a real Linux/Kali environment. They must be run in the project's virtual environment on the target system.

## Release validation notes
- Application version is centralized in `nemos/version.py`.
- Package metadata and API health version are synchronized to the internal release version in `nemos/version.py`.
- Capture state reporting and shutdown lifecycle fixes are included.
- Systemd capability bounding is limited to `CAP_NET_RAW`.
- No virtual environment, runtime database, logs, `.pyc`, or `.env` files are included in the release archive.
