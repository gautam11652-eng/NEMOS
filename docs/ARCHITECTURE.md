# Architecture

## Design principles

Two constraints shape almost every decision in this codebase.

**The capture path stays cheap.** A packet handler that blocks is a packet
handler that drops traffic. Detection is pure in-memory state that never touches
the filesystem or SQLite. Persistence and outbound delivery are both handed to
background threads through bounded queues.

**State keyed by an attacker-influenceable value must be bounded.** A source
address can be spoofed arbitrarily. Every map keyed by one — event buckets,
behavioural profiles, ARP mappings, alert cooldowns, incident correlation,
delivery cooldowns — has an explicit eviction bound, so a spoofing flood costs
CPU rather than unbounded memory.

## Data flow

```
network interface
      │
      ▼
capture.py ──────────► TrafficEvent
      │                     │
      │        ┌────────────┼────────────────► storage.py ──► SQLite (WAL)
      │        │            │                                      │
      ▼        ▼            ▼                                      ▼
detector.py  flows.py    (traffic rows)                        api.py
   (rules)   (unidirectional flow table)                           │
      │        │                                                   ▼
      │        │  ── analysis.py: background thread ──         dashboard
      │        │     window expiry                                 ┊
      │        ▼        │                                          ┊ optional
      │     features.py │  24 features per source per window       ▼
      │        │        │                                     analyst.py
      │        ├────────┴──► ml.py (Isolation Forest)         (explains only)
      │        └───────────► behavioral.py (EMA baseline)
      │                          │
      └──────────────────────────┴──► fusion.py
                                          │
                                       Alert ──┬──► storage.py  (persist first)
                                               └──► notify.py   (deliver second)
```

The split matters: `detector.py` runs inline on the capture thread because its
rules are cheap and should fire on the packet that triggers them. Everything
inside `analysis.py` runs on its own thread on a fixed cadence, so feature
extraction and model inference can never add latency to packet capture.

## Modules

| Module | Responsibility |
| --- | --- |
| `main.py` | Process lifecycle: configuration, startup order, signal handling, ordered shutdown |
| `nemos/env.py` | Minimal `.env` parser; no interpolation, no substitution, existing environment wins |
| `nemos/config.py` | Environment-derived `Settings` with range clamping and bind-safety validation |
| `nemos/capture.py` | The only Scapy adapter. Translates packets into typed `TrafficEvent` objects and reports capture state |
| `nemos/models.py` | `TrafficEvent` and `Alert` dataclasses — the boundary types between layers |
| `nemos/detector.py` | Deterministic rules over bounded sliding windows; owns incident correlation |
| `nemos/flows.py` | Unidirectional flow aggregation, bounded with O(1) LRU eviction |
| `nemos/features.py` | 24 numeric features per source per window; no ML dependency |
| `nemos/ml.py` | Isolation Forest: training, persistence, calibration, scoring |
| `nemos/fusion.py` | Transparent combination of rules, baseline and ML into one risk |
| `nemos/analysis.py` | The background windowed-analysis thread tying those together |
| `nemos/analyst.py` | Optional LLM explanation layer; performs no detection |
| `nemos/behavioral.py` | Per-source exponentially weighted baseline over four traffic features |
| `nemos/intelligence.py` | Incident-level triage scoring and analyst recommendations |
| `nemos/attack.py` | MITRE ATT&CK catalog and presentation-only alert enrichment |
| `nemos/storage.py` | The single SQLite writer thread: batching, retention, backpressure |
| `nemos/database.py` | Schema, indexes, pragmas and additive migrations |
| `nemos/notify.py` | Outbound alert delivery to Telegram and webhooks |
| `nemos/api.py` | The Flask application: JSON API, auth, security headers |

## Detection

Detection has three independent layers, kept distinguishable in the data model,
the API and the interface. They answer different questions and can evidence
different things: only deterministic rules can name a MITRE ATT&CK technique.

### Deterministic rules

`detector.py` maintains a bounded deque of recent events per source. Within a
sliding window it derives unique destination ports, unique destinations, SYN-only
TCP packets, UDP ports, ICMP destinations and service-port hits, then applies
explicit thresholds. Each finding carries the evidence that produced it.

A per-`(source, threat)` cooldown suppresses duplicate findings, and that
cooldown map is itself bounded.

### Statistical baseline

`behavioral.py` maintains an exponentially weighted mean and variance for four
features per source: packet rate, byte rate, unique destinations and unique
ports.

This is a statistical model, not a trained one. It is deliberately not machine
learning, and the code says so. Every anomaly is explainable as a numeric
deviation from that source's own observed history. Three properties keep it
defensible:

- **Fixed sampling cadence.** A rolling packet window can produce the same
  observation hundreds of times; sampling on a cadence stops the baseline from
  adapting to the burst it exists to catch.
- **Per-feature noise floors.** An exponentially weighted variance can be
  legitimately zero during a stable warm-up. Without a floor, a one-unit change
  would produce an effectively infinite z-score.
- **Independent corroboration.** Rate and byte rate are correlated, so the
  strongest deviation must be supported by an independent dimension —
  destination or port diversity — unless it is extreme.

Evidence records the baseline *before* it was updated with the observation being
judged, so the alert describes what the event was actually compared against.

### Correlation and scoring

Alerts from the same source within a bounded window share a stable
`incident_id`. `intelligence.py` combines the strongest constituent alert with
capped bonuses for independent signals — distinct threats, distinct techniques,
critical findings and evidence count — into an incident risk score. The
computation is deliberately arithmetic and readable rather than opaque.

### ATT&CK mapping

`attack.py` holds a small catalog of only those techniques the detector actually
emits. Mapping is evidence-backed: a generic behavioural anomaly is reported as
an unmapped signal with a stated reason rather than being assigned a technique
the observation does not support. Technique IDs are stored on alerts; names and
tactics live in the catalog so presentation metadata can be corrected without
rewriting historical alerts.

## Unidirectional flows

The flow key is `(source, destination, source_port, destination_port, protocol)`
used exactly as observed. There is no canonicalisation, so A→B and B→A are two
records that are never merged — a one-way tap is a first-class deployment, and
direction is what distinguishes one host contacting two hundred destinations
from two hundred hosts answering.

The table is bounded with O(1) least-recently-observed eviction via an
`OrderedDict`. That is not a micro-optimisation: a flow key contains
attacker-controlled values, so a spoofing flood creates a new key per packet.
An earlier implementation scanned for the oldest entry, making eviction O(n) per
packet exactly when the table was full — turning the bound that exists to
survive the flood into the bottleneck.

## Machine learning

`ml.py` wraps a scikit-learn Isolation Forest. Three properties make its output
defensible rather than merely impressive:

- **The score is not a probability.** It measures depth into the tail of the
  training distribution in robust deviation units anchored on the median and
  5th percentile — never the minimum, which is a single sample that one unusual
  training window can use to set the entire scale.
- **The feature contract is versioned and enforced.** Schema version, feature
  names *and* the aggregation window are recorded at training time and checked
  at load. Counts and rates scale with the window, so a model fitted on 10s
  windows applied to 2s windows would score a distribution it never saw; NEMOS
  refuses rather than reporting confident, wrong numbers.
- **Absence degrades, never fails.** scikit-learn missing, no model, a corrupt
  file or a mismatched schema all leave the engine unavailable with a stated
  reason while rules and the baseline continue unaffected.

Training is out-of-band by design (`tools/train_model.py`). A sensor that
retrained itself on live traffic would learn to accept whatever it is currently
seeing, including an intrusion in progress.

## Fusion

`fusion.py` combines the layers under rules that encode what each can actually
evidence: deterministic findings set the risk floor and are the only source of a
MITRE ATT&CK technique; statistical layers may raise a score but never lower it,
and alone are capped below CRITICAL. Every assessment carries the arithmetic in
its `explanation` field — a reviewer who cannot reproduce the score by hand has
found a bug.

## Storage

`storage.py` owns the only writer. Callers submit to a bounded queue and the
worker commits in batches.

- **Priority-aware backpressure.** Alerts get a reserved portion of the queue and
  a short blocking window, so a packet flood cannot starve security findings.
  Traffic is lossy under sustained overload by design; capture must not block.
- **Incremental counters.** Telemetry totals and per-host summaries are updated
  from the rows in each committed transaction rather than recomputed, keeping
  dashboard reads O(1) instead of full-table scans.
- **Retention.** Traffic and alert tables are pruned to configured row limits,
  with counter deltas applied from the pruned rows and per-host risk fields
  repaired only for hosts whose maxima may have changed.
- **Lock handling.** Batches retry with backoff on SQLite lock contention;
  a failed batch is counted, never silently dropped.

## Delivery

`notify.py` runs a worker thread behind a bounded queue. Ordering matters:
`main.py` persists an alert before submitting it for delivery, so an unreachable
channel cannot cost a recorded detection.

Outbound volume is bounded by a severity floor, a per-finding cooldown and a
global token bucket — a port scan must not turn the sensor into an amplifier.
Suppressed alerts remain stored and visible; only the outbound copy is dropped,
and each suppression is counted.

Webhook URLs must be HTTPS unless loopback, and redirects are refused rather
than followed. The Telegram bot token travels in the request URL, so it is
redacted from every log line, error string and API response.

## Web layer

`api.py` is the single web application. `/api/dashboard` consolidates what the
interface needs into one request, guarded by an ETag derived from the telemetry
revision plus capture state, so a sensor failure invalidates the cache even when
stored telemetry has not changed.

Defaults are loopback-only. A non-loopback bind requires an API token; a
wildcard bind additionally requires an explicit trusted-host list. Mutating
endpoints reject cross-site browser writes even when no token is configured.
Production deployments should still place HTTPS and network controls in front of
the application.

## Shutdown

`main.py` closes the HTTP server, stops capture, drains delivery, then drains the
writer — in that order, so nothing still producing alerts outlives the machinery
that stores them.
