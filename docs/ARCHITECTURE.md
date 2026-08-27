# Architecture

`main.py` owns lifecycle.

`capture.py` is the only packet-capture adapter. It translates Scapy packets into typed `TrafficEvent` objects.

`detector.py` is pure in-memory detection state. It does not touch files or SQLite, preventing packet processing from blocking on I/O.

`storage.py` owns the only SQLite writer thread. Events are queued and committed in batches.

`database.py` defines the schema, indexes and SQLite pragmas.

`api.py` is the single web application. `/api/dashboard` consolidates dashboard reads into one request. O(1) dashboard counters are maintained in the `telemetry_stats` singleton table and refreshed by the writer.

`templates/index.html` is a self-contained SOC-style interface.

The system defaults to loopback-only HTTP. A remote bind requires an API token, and configured tokens protect all API endpoints except the public health check. Production deployments should still put HTTPS/authentication/network controls in front of the application.

### Detection Engine v2

NEMOS uses deterministic rules plus a conservative per-source behavioural baseline. The baseline is an exponentially weighted moving average (EMA) of recent packets-per-second and is only eligible to alert after a minimum number of observations and a minimum burst size. This keeps the feature explainable and offline while avoiding a claim of opaque ML inference.

Alerts from the same source are correlated into a bounded incident window and receive a stable `incident_id`. The dashboard and `/api/incidents` endpoint expose the correlated view without requiring a separate event-correlation service.

### Telemetry statistics

The SQLite writer updates aggregate telemetry counters from the rows inserted in each successful transaction. This avoids full-table `COUNT/SUM` scans on every flush. When retention pruning deletes rows, NEMOS performs a one-time recount so aggregate counters remain exact.
