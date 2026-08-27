# NEMOS Local Verification

Date: 2026-08-26

## Current verification

- Python compilation: PASS
- JavaScript syntax (`node --check`): PASS
- Dependency-independent regression suite: **42 tests passed**
- Dashboard DOM contract: PASS
- Dashboard branding/navigation contract: PASS
- Dashboard element-reference check: PASS
- No inline `style=` attributes in dashboard HTML/JS: PASS
- No `THREATCORE` branding in dashboard source: PASS
- Static dangerous-call scan: PASS
- systemd packet-capture family check (`AF_NETLINK` + `AF_PACKET`): PASS
- Kali verification script path check: PASS
- Offline detection validation: PASS

## Dashboard review

The dashboard was redesigned for a restrained operational interface rather than a highly stylized/futuristic presentation. It now uses:

- clear information hierarchy
- neutral slate/white surfaces
- restrained blue accents
- color reserved for severity/status
- simpler navigation and tables
- improved readability and spacing
- the existing investigation, host, incident, technique and network workflows preserved

The JavaScript continues to use the existing API contracts for dashboard refresh, incident investigation, host investigation and alert acknowledgement. The packet-capture service sandbox now permits the Linux socket families Scapy requires for interface discovery and raw capture.

## Environment limitation

The verification container does not have internet access and does not ship with the runtime dependencies Flask, Scapy, and Waitress. Therefore the Flask API suite, real Waitress server lifecycle, and live packet-capture integration cannot be executed here. This is an environment limitation, not a test failure.

The target Kali environment should run the complete suite after installing the pinned dependencies with:

`python -m pip install -r requirements.txt`

`python -m pytest -q`
