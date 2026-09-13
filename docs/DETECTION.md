# Detection

NEMOS runs three independent layers and keeps them distinguishable in the data
model, the API and the interface. They answer different questions:

| Layer | Question it answers | Can name an ATT&CK technique? |
| --- | --- | --- |
| Deterministic rules | Was a specific, named behaviour observed? | Yes |
| Statistical baseline | Is this host behaving unlike *itself*? | No |
| ML anomaly model | Is this window unlike the *trained* traffic? | No |

## Deterministic rules

Bounded, stateful counters over a sliding window produce 27 findings. Each
carries the evidence that triggered it — the ports observed, the SYN ratio, the
destination count — and every finding whose evidence cannot support a stronger
claim says so in its own evidence.

| Stage | Findings |
| --- | --- |
| Reconnaissance | `PORT_SCAN` (external source), `TCP_SYN_SCAN`, `UDP_PORT_SCAN`, `TCP_NULL_SCAN`, `TCP_FIN_SCAN`, `TCP_XMAS_SCAN` |
| Discovery | `PORT_SCAN` (internal source), `NETWORK_FANOUT`, `ICMP_SWEEP`, `SERVICE_CONNECTION_BURST` |
| Credential access | `CREDENTIAL_BRUTE_FORCE`, `PASSWORD_SPRAYING`, `ARP_MAPPING_CHANGE` |
| Lateral movement | `LATERAL_MOVEMENT` (names RDP, SMB, SSH, VNC or WinRM from the observed port) |
| Command and control | `C2_BEACONING`, `DNS_TUNNELING_PATTERN`, `ICMP_TUNNELING_PATTERN`, `TOR_CONNECTION_PATTERN`, `NON_STANDARD_PORT_TRAFFIC`, `INGRESS_TOOL_TRANSFER`, `DNS_BURST` |
| Exfiltration | `DATA_EXFILTRATION_VOLUME`, `DATA_EXFILTRATION_OVER_C2` |
| Impact | `SYN_FLOOD_PATTERN` (requires SYNs concentrated on one service — a port sweep of the same volume is a scan, not a flood), `ICMP_FLOOD_PATTERN`, `SERVICE_DENIAL_OF_SERVICE`, `REFLECTION_AMPLIFICATION`, `CRYPTO_MINING_PATTERN` |

Three of these are worth singling out:

- **`C2_BEACONING`** measures the coefficient of variation of the intervals
  between contacts with one destination. Periodicity is where a unidirectional
  tap is strongest: the callback is visible without ever seeing a reply. Known
  periodic services (NTP, DNS, DHCP) are excluded, because flagging them would
  bury real callbacks in benign noise.
- **`DATA_EXFILTRATION_OVER_C2`** is not a separate signal but a correlation:
  bulk transfer to a host the same source was *already* beaconing to. Two
  findings combining into a stronger claim than either supports alone.
- **`PASSWORD_SPRAYING`** exists because `CREDENTIAL_BRUTE_FORCE` counts per
  target and therefore cannot see it — few attempts each, across many hosts, is
  precisely the shape that evades per-account lockout.

Port-based identifications (mining, Tor, non-standard ports) are heuristics and
are labelled as such in their own evidence, with confidence set accordingly.

On an ordinary (bidirectional) interface NEMOS also sees the replies to your own
connections. Those are recognised and excluded from scan analysis — otherwise
every server that answered several clients would be reported as a port scanner.
Probes are never excluded, so a genuine sweep still fires whatever source port
it comes from.

## Statistical baseline

Each source host gets a profile of four features: packet rate, byte rate, unique
destinations and unique ports. Each is tracked as an exponentially weighted mean
and variance, sampled on a fixed cadence so a rolling window cannot let the
baseline quietly adapt to the burst it is supposed to catch.

Three properties keep this honest:

- **Warm-up.** A profile cannot raise an alert until it has `MIN_SAMPLES`
  observations. A host with no history is never called anomalous.
- **Noise floors.** A zero variance during a stable warm-up cannot turn a
  one-unit change into an effectively infinite z-score.
- **Corroboration.** The strongest deviation must be supported by an independent
  dimension unless it is extreme, so a single noisy feature is not treated as
  hostile.

Baseline state is always one of `NO_BASELINE`, `NORMAL`, `DEVIATING` or
`HIGHLY_DEVIATING`. A host without enough history is `NO_BASELINE` — never
"normal" and never "anomalous", because the evidence supports neither.

**This is a statistical model, not a trained one**, and NEMOS does not call it
AI or ML anywhere.

## Machine-learning anomaly detection

An **Isolation Forest** (scikit-learn) fitted on feature vectors from traffic
you consider benign. It is unsupervised: it is never shown an attack, only what
ordinary traffic on *your* network looks like, and it reports how unusual a
window is relative to that.

**Why Isolation Forest.** The requirement is to flag unusual traffic without
labelled attack data, on a live sensor, explainably. Isolation Forest fits: it
needs no labels, trains in seconds on tens of thousands of windows, scores in
sub-millisecond time per window, has no distance metric to tune, and degrades
gracefully in the moderate dimensionality (24 features) used here. Local Outlier
Factor scores by local density and needs the training set retained at inference,
which is heavier for a long-running sensor. One-Class SVM scales poorly with
sample count and is sensitive to kernel and `nu` choices that are hard to
justify to a reviewer. Both remain reasonable alternatives; the engine is a
single class behind a small interface if you want to substitute one.

**Features** — 24 per source per window, all derivable from observed metadata,
none from payload (TLS handshake fingerprints are recorded as evidence but are
deliberately not model features; see [Encrypted traffic](#encrypted-traffic)):

| Group | Features |
| --- | --- |
| Volume | `packets`, `bytes`, `packets_per_second`, `bytes_per_second` |
| Flow shape | `flow_count`, `mean_flow_duration`, `mean_packets_per_flow`, `mean_bytes_per_flow` |
| Fan-out | `unique_destinations`, `unique_destination_ports`, `unique_source_ports` |
| Dispersion | `destination_entropy`, `destination_port_entropy` |
| Packet size | `mean_packet_size`, `stddev_packet_size`, `small_packet_ratio` |
| TCP flags | `syn_ratio`, `ack_ratio`, `rst_ratio`, `fin_ratio` |
| Protocol mix | `tcp_ratio`, `udp_ratio`, `icmp_ratio`, `dns_ratio` |

Entropy earns its place: it separates "many packets to one destination" from
"many packets spread evenly across destinations", which a unique count cannot.

**The anomaly score (0–100) is not a probability.** `decision_function` returns
an unbounded, scale-free number. At training time NEMOS records that value's
distribution; at inference a window is placed against it in **robust deviation
units**:

```
deviation = (median − raw) / (median − 5th percentile)
```

| Deviation below the training median | Score | Band |
| --- | --- | --- |
| up to 1 unit | 0 | NORMAL |
| 1 – 2 units | 0 – 40 | NORMAL |
| 2 – 2.5 units | 40 – 70 | SUSPICIOUS |
| beyond 2.5 units | 70 – 100 | ANOMALOUS / HIGHLY_ANOMALOUS |

Both anchors are robust by design. An earlier implementation anchored on the
training *minimum* and was wrong in an instructive way: the minimum is a single
sample, so one unusual training window set the whole scale — measured here it
sat at −0.255 against a 5th percentile of −0.030, stretching the band until a
259-port SYN scan scored 65. The bands above come from measured separation on
the bundled scenarios: held-out normal traffic reached 1.7 deviation units,
every abnormal scenario fell between 2.6 and 3.3.

**Explainability.** An Isolation Forest exposes no per-feature attribution, so
NEMOS reports which features are furthest from their training mean, in standard
deviations. A real assessment from the bundled port-scan scenario:

```
anomaly 94/100 (highly anomalous)
  unique destination ports is 317.2 standard deviations above the training mean
  flow count is 288.1 standard deviations above the training mean
  packets per second is 48.5 standard deviations above the training mean
```

**The aggregation window is part of the model contract.** Counts and rates scale
with it, so a model fitted on 10-second windows describes a different
distribution from one applied to 2-second windows. Training records the window;
loading refuses a mismatch rather than producing confident, wrong scores.

## Hybrid risk fusion

The three layers are combined by an explicit, reproducible formula — never
`final = ml_score × 100`.

**When a deterministic rule fired:**

```
risk = strongest rule risk          (the floor)
     + ML contribution              (0–25, scaled above the NORMAL band)
     + baseline contribution        (0, 8 or 15 by state)
     + corroboration bonus          (10 when a statistical layer agrees)
     capped at 100
```

**When no rule fired**, statistics must carry the finding alone, under a
stricter mapping and a lower ceiling:

```
risk = max(ML tail risk, baseline risk)     — max, not sum: the two are usually
     + 10 if both fired                       two views of one underlying change
     capped at 84                            — statistical evidence alone cannot
                                               reach CRITICAL
```

Nothing below the ANOMALOUS band contributes on this path: a merely SUSPICIOUS
window is the ordinary jitter of real traffic, and alerting on it trains
operators to ignore the sensor.

Every assessment carries the arithmetic in its `explanation` object. If you
cannot reproduce the risk score by hand from the signals, that is a bug.
Verdicts are worded for what was observed — `POSSIBLE_RECONNAISSANCE`,
`BEHAVIOR_CONSISTENT_WITH_ATTACK` — never "confirmed attack".

Incidents combine the strongest constituent alert with bounded bonuses for
independent signals; see [`nemos/intelligence.py`](../nemos/intelligence.py).

## ATT&CK mapping

A technique ID is attached only where the observed network behaviour supports
it. Scanning maps to `T1046`; DNS tunnelling patterns to `T1071.004`; floods to
`T1498`/`T1498.001`; ARP manipulation to `T1557.002`. A generic behavioural
anomaly is reported as an unmapped signal with a stated reason, rather than
being assigned a technique it does not evidence.

## Unidirectional traffic

The SIH problem statement concerns **unidirectional IP traffic**, and NEMOS
takes that literally rather than assuming both halves of a conversation are
visible.

A flow is keyed by the five-tuple exactly as observed:

```
(source, destination, source_port, destination_port, protocol)
```

There is no canonicalisation and no address ordering. Traffic from A to B and
traffic from B to A produce **two independent records that are never merged**.
Two reasons:

- A one-way tap, a SPAN port carrying a single direction, or an asymmetric route
  may only ever show one side. A representation assuming both directions would
  silently misreport in exactly that deployment.
- Direction carries the signal. One host contacting two hundred destinations is
  reconnaissance; two hundred hosts answering it is not. Merging the directions
  destroys the asymmetry detection depends on.

**No feature requires a response packet.** Every one of the 24 features is
computed from the observed direction alone — counts, rates, per-flow statistics,
flag ratios, protocol ratios and entropies. Nothing is inferred from traffic
that was never seen, and no feature is silently defaulted to stand in for a
missing reverse flow.

Where reverse traffic *is* available and correlation is wanted,
`FlowTable.reverse_of()` returns the opposite record without modifying or
merging either side. Both directions remain separate rows in the `flows` table
and in `GET /api/flows`.

## Encrypted traffic

Most traffic worth watching is now inside TLS, which is the blind spot every
metadata-only sensor has: NEMOS can see that a host opened a session and how
much crossed it, but not what was said.

The handshake is the exception. Before a session key exists, client and server
negotiate in cleartext — which versions, ciphers, extensions and curves they
support. That negotiation is a property of the *software*, not of the user, and
it is distinctive: Chrome, curl, python-requests, Go's `crypto/tls` and a
Cobalt Strike beacon all present recognisably different handshakes. **JA3** is
the standard hash of that negotiation, and NEMOS computes it for every
handshake it sees, in both directions (JA3S for the server).

**What is read, precisely.** The ClientHello and ServerHello, and nothing else.
Application data — everything after the handshake — is ciphertext and is never
parsed. NEMOS does not decrypt, does not proxy, and does not need a private
key. The one field that identifies a destination rather than software is the
SNI (the hostname the client asks for), which is recorded because it is the
field that makes a finding actionable.

**GREASE is stripped.** RFC 8701 has clients inject reserved values into their
cipher and extension lists specifically so middleboxes cannot assume the lists
are fixed, and Chrome picks different ones on every connection. Hashing the
lists as they arrive gives a browser a brand-new fingerprint per connection,
which makes JA3 worse than useless. NEMOS removes them before hashing, so a
fingerprint is stable across connections from the same software.

### What this detects, and what it does not

| Finding | Technique | What it means |
| --- | --- | --- |
| `TLS_ON_UNEXPECTED_PORT` | T1571 | Confirmed TLS handshakes to an external host on a port that is not a TLS port. Because the handshake is unmistakable, this knows the traffic really is TLS rather than guessing from the port number. |

Fingerprints are also attached as **evidence** to every command-and-control
finding, which is the larger practical win: a beaconing alert that carries a
JA3 can be pivoted on — across this network, across other tooling, across
public corpora — where "talked to 203.0.113.9" leads nowhere.

**NEMOS ships no list of known-malicious JA3 hashes, on purpose.** Such lists
go stale quickly, collide with common libraries (a great deal of malware uses
stock Go or Python TLS, and so does a great deal of legitimate software), and
shipping one would claim a detection quality that cannot be validated here.
The fingerprint is recorded so *you* can pivot on it; it is never treated as a
verdict.

**Fingerprint diversity is evidence, never its own alert.** A workstation
speaks TLS with a small, stable set of client software, so a host presenting
many distinct handshakes is worth an analyst's attention. But behind NAT one
address aggregates every host behind it and reaches any threshold honestly, so
this could not earn a standalone confidence. It appears in evidence, with that
caveat stated inline, and strengthens a finding rather than making one.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEMOS_DETECT_TLS_HORIZON` | `900` | How long a fingerprint stays associated with a source, in seconds |
| `NEMOS_DETECT_TLS_MAX_FINGERPRINTS` | `6` | Distinct fingerprints from one address before diversity is noted in evidence |
| `NEMOS_DETECT_TLS_ODD_PORT_HANDSHAKES` | `3` | Handshakes on a non-TLS port before it is reported |
| `NEMOS_DETECT_TLS_MAX_TRACKED` | `16` | Bound on fingerprints, names and ports retained per source |
