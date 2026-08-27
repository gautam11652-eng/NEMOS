# NEMOS Audit Update

Date: 2026-08-26

## Latest fixes

- Fixed the systemd sandbox that blocked Scapy RTNETLINK/interface discovery with `OSError: [Errno 97] Address family not supported by protocol`. The service now permits `AF_NETLINK` and `AF_PACKET` while retaining the `CAP_NET_RAW` capability boundary.
- Fixed a misleading capture-interface label when no explicit interface is configured.
- Fixed the Kali verification script's stale uppercase static-file path.
- Fixed SQLite batch-failure logging so the actual exception is retained instead of emitting an empty `log.exception()` record after retries.
- Standardized the default manual-install database filename to `data/nemos.db`.
- Bumped the application version to 3.2.6.

## Verification

- Python compilation: PASS
- Dashboard JavaScript syntax: PASS
- Bash syntax for installer and verifier: PASS
- Dependency-independent regression tests: **42 passed**
- Dashboard DOM/branding/navigation checks: PASS
- Offline detection validation: PASS
- AF_NETLINK and AF_PACKET raw socket availability in the audit environment: PASS

The audit environment does not contain Flask, Scapy, or Waitress and has no package-index network access, so the dependency-dependent Flask API suite and live Scapy/Waitress integration cannot be honestly marked as executed here. The target Kali installation should run the complete suite after installing `requirements.txt`.

---

# NEMOS Final Audit

## Verified in the isolated build environment

- Python AST/bytecode compilation: PASS
- 31 dependency-independent tests: PASS
- Static dangerous-call scan (`eval`, `exec`, `pickle.loads`, shell execution): PASS
- No stale NEXORA/nexora/CS- identifiers in source tree: PASS
- Dashboard polling is visibility-aware and 10 seconds by default: PASS
- Dashboard uses a revision-based ETag for conditional refresh: PASS
- Dashboard host summaries use materialized `host_stats`: PASS
- `/api/hosts` uses the materialized host index instead of full traffic/alert GROUP BY scans: PASS
- SQLite batch writer and retention logic inspected: PASS
- DNS telemetry path inspected and covered by regression tests: PASS
- Shutdown path uses a dedicated `ShutdownRequested` control-flow exception and bounded capture/writer cleanup: PASS

## Environment-dependent verification

The isolated environment used for this audit does not contain Flask/Scapy/Waitress and cannot install packages from PyPI. Therefore the Flask API integration suite and live packet-capture integration cannot honestly be marked as executed here. Those require the target Kali environment.

The final package is intended to be installed from `requirements.txt` and tested with `python -m pytest -q` on Kali.
