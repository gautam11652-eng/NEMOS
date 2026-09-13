# Detection benchmark

Throughput is not detection quality. `tools/benchmark.py` answers "how many
packets per second"; this answers the question that decides whether a detector
is worth deploying:

```bash
python tools/benchmark_detection.py
python tools/benchmark_detection.py --repeats 20 --json results.json
```

Every scenario in `tools/scenarios.py` carries machine-readable ground truth
(`Scenario.expected`) decided from the **traffic shape**, independently of what
NEMOS emits. That independence is the point — labelling scenarios with whatever
the detector already finds would make recall 1.0 by construction.

## Results

20 replays per scenario, each with a different seed, on the committed defaults
(10s window, confidence floor 55). Reproduce with the command above.

| Detection | Precision | Recall | F1 | FP on benign |
| --- | ---: | ---: | ---: | ---: |
| PORT_SCAN | 100% | 100% | 100% | 0 |
| TCP_SYN_SCAN | 100% | 100% | 100% | 0 |
| UDP_PORT_SCAN | 100% | 100% | 100% | 0 |
| ICMP_SWEEP | 100% | 100% | 100% | 0 |
| ICMP_FLOOD_PATTERN | 100% | 100% | 100% | 0 |
| DNS_BURST | 100% | 100% | 100% | 0 |
| SYN_FLOOD_PATTERN | 100% | 100% | 100% | 0 |
| SERVICE_CONNECTION_BURST | 100% | 100% | 100% | 0 |
| BEHAVIORAL_TRAFFIC_ANOMALY | 100% | 100% | 100% | 0 |
| SERVICE_DENIAL_OF_SERVICE | 66.7% | 100% | 80% | 20 |
| NETWORK_FANOUT | 33.3% | 100% | 50% | 40 |

**Overall: recall 100%, precision 58.2%, F1 73.6%** — 160 true positives, 0
false negatives, 115 false positives across 80 benign replays (1.44 per
replay). Median detection latency **1.20s** of scenario time.

## The false positives are real, and not tuned away

Recall is 100% because the attack scenarios are unambiguous. Precision is 58%
because the benign corpus is deliberately hard: three of the four benign
scenarios are *legitimate traffic shaped like an attack*, which is where real
false positives come from.

| Benign scenario | What NEMOS says | Why |
| --- | --- | --- |
| `nat_gateway` | NETWORK_FANOUT, PASSWORD_SPRAYING | One address speaking for a whole office contacts many destinations on many ports. Indistinguishable from a scan without knowing it is a gateway |
| `monitoring_host` | NETWORK_FANOUT | A metrics poller contacting 39 hosts on a schedule is shaped exactly like discovery |
| `backup_window` | C2_BEACONING, CREDENTIAL_BRUTE_FORCE, SERVICE_DENIAL_OF_SERVICE | A nightly bulk transfer to an SMB server looks like exfiltration, brute force and a flood at once |

These are **not** bugs to be fixed by raising thresholds. Each is a case where
packet metadata genuinely does not carry the distinguishing information — the
difference is authorisation and role, which no amount of header inspection
reveals. The honest fix is context (an asset inventory that knows which address
is the gateway, the poller and the backup target), not a threshold that makes
the number look better while blinding the detector to the real version of the
same shape.

An earlier version of this benchmark measured only against `normal_traffic`,
which is *paced below the detector's thresholds by construction*, and reported
100% precision with zero false positives. That figure was close to circular and
has been removed rather than quoted.

## What it does not measure

- **The ML model.** These figures are the deterministic rules only. Nothing
  here evaluates the Isolation Forest; see the note under Training.
- **Real network traffic.** The corpus is synthetic. It exercises the shapes the
  rules target, not the messiness of a production network.
- **Evasion.** Nothing here is paced to slip under a window deliberately; see
  `nemos/slowscan.py` for the tier that addresses that, which this does not
  score.

## Demonstration

A controlled, offline demonstration of the whole pipeline across nine traffic
scenarios:

```bash
python tools/demo.py                        # all scenarios
python tools/demo.py --scenario port_sweep  # one
python tools/demo.py --no-train             # the rules-only degraded path
```

Everything is generated in memory using RFC 5737 documentation addresses. No
packet is transmitted, no interface is touched, no host is contacted. The
scenarios are traffic *shapes*, not exploits.

Scenarios: normal traffic, connection burst, destination fan-out, port sweep,
abnormal TCP (SYN flood pattern), unusual UDP, DNS deviation, sudden rate
deviation, ICMP sweep.

Results from the bundled run — normal traffic produces no finding, and every
abnormal scenario is detected:

| Scenario | Flows | Rules | Anomaly | Risk | Verdict |
| --- | --- | --- | --- | --- | --- |
| normal_traffic | 189 | 0 | – | 0 | NO_FINDING |
| connection_burst | 396 | 2 | 100 | 100 | POSSIBLE_RECONNAISSANCE |
| destination_fanout | 199 | 3 | 91 | 100 | POSSIBLE_RECONNAISSANCE |
| port_sweep | 259 | 3 | 94 | 100 | POSSIBLE_RECONNAISSANCE |
| abnormal_tcp | 621 | 2 | 100 | 100 | POSSIBLE_RECONNAISSANCE |
| unusual_udp | 119 | 2 | 100 | 100 | POSSIBLE_RECONNAISSANCE |
| dns_deviation | 300 | 1 | 100 | 100 | BEHAVIOR_CONSISTENT_WITH_ATTACK |
| rate_deviation | 1239 | 2 | 84 | 100 | POSSIBLE_RECONNAISSANCE |
| icmp_sweep | 119 | 3 | 100 | 100 | POSSIBLE_RECONNAISSANCE |

## Performance

Every number here comes from `tools/benchmark.py`, which ships in the
repository so you can check it on your own hardware rather than trusting it:

```bash
python tools/benchmark.py
```

Measured on Python 3.11 at the tool's default of 20,000 packets per profile,
on a dedicated machine:

| Profile | Distinct sources | Packets/sec | µs/packet |
| --- | ---: | ---: | ---: |
| Small LAN | 50 | 5,059 | 197.7 |
| Office | 500 | 29,147 | 34.3 |
| Large segment | 5,000 | 38,319 | 26.1 |
| Spoofing flood | 50,000 | 31,654 | 31.6 |

These are one machine's numbers, not a specification. A shared or virtualised
host will report considerably less — run the benchmark on the hardware you
intend to deploy on and plan against what it tells you.

**Read the slowest row, not the fastest.** Detection cost is driven by how many
events sit in a source's window, not by the packet rate. A few busy hosts fill
their windows to `max_events` and cost the most per packet; a spoofing flood
spreads packets across thousands of short-lived windows and costs less each.
Quoting the peak would overstate what the sensor does on exactly the small,
busy network most people deploy it on.

**Known limitation.** Per-packet cost is linear in window size. Every rule
reads from one aggregate rather than scanning the window itself, but that
aggregate is still built by a single pass per packet. Removing the linearity
requires incremental counters maintained on append and eviction, which NEMOS
does not do today. If your link exceeds these rates, lower `NEMOS_MAX_EVENTS`
or run capture on a mirrored subset.

Bounded state is verified by the same script: under 60,000 packets from
spoofed sources, every map keyed by an attacker-controlled value stays inside
its configured bound.
