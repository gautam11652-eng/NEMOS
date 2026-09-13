# Replaying capture files

`tools/replay_pcap.py` runs a `.pcap`/`.pcapng` through the same parser and the
same detection rules a live sensor uses, offline. It exists because
`tools/benchmark_detection.py` measures a **synthetic** corpus, and synthetic
traffic cannot answer two questions:

1. **Does the parsing layer survive real packets?** Production captures carry
   truncated headers, VLAN tags, tunnels, bad checksums and link types a
   generator never emits.
2. **What does NEMOS detect on labelled traffic?** With an attack schedule,
   every finding is scored against ground truth.

Nothing in this path transmits. It opens a file.

```bash
python tools/replay_pcap.py capture.pcap
python tools/replay_pcap.py capture.pcap --labels schedule.json --json out.json
python tools/replay_pcap.py huge.pcap --limit 2000000        # sample a prefix
```

## The clock comes from the packets

This is the property the tool is built around. The detector's window is driven
by each packet's own recorded timestamp, not by how fast the file is read.

Replaying an hour of traffic in a second would put every packet inside one
10-second window and manufacture findings. That is not hypothetical — it is
measured, on a real capture of a deliberately slow sweep (27 ports over 104
seconds, about 3 per window against a `port_scan` rule of 8):

| Clock | Findings |
| --- | --- |
| Packet timestamps (what the tool does) | **none** — correctly, the sweep is under the rule |
| Wall clock (what a naive replay does) | **PORT_SCAN** — an artifact of reading 104s of traffic in 0.57s |

Both directions are pinned in `tests/test_replay_pcap.py`, including the
wall-clock case: if compressing the replay ever *stops* fabricating that
finding, the guard has stopped being load-bearing and the test says so.

## The parser is the live one

`PacketCapture._parse` and `PacketCapture._parse_arp` are called directly.
There is no second parser to drift — which is why the ARP branch was lifted out
of the sniff callback rather than copied here.

## Reading the parse report

```
PARSING
  packets read        1,482,309
  parsed to an event  1,481,940
  not IP/IPv6/ARP           312
  malformed                  57 (0.0038%)
      IndexError                 57
  out of order              104  (windows assume a forward clock; sort the file if this is large)
```

- **malformed** — the packet raised inside the parser. Counted by exception
  type rather than swallowed: a parser that silently skips 3% of a capture is
  worse than one that crashes, because the sensor looks healthy.
- **not IP/IPv6/ARP** — parsed fine, carries nothing NEMOS rules on (STP, LLDP,
  pure L2). Not an error.
- **out of order** — a packet older than its predecessor. A handful is normal
  on a multi-interface capture. A flood means the file needs sorting first,
  because the detection windows assume a clock that runs forwards.

## Ground truth

`--labels` takes a JSON schedule. `sources`/`targets` may be omitted, which
means "any address":

```json
{
  "name": "example day",
  "attacks": [
    {
      "label": "FTP-Patator",
      "start": "2017-07-04T09:20:00+00:00",
      "end":   "2017-07-04T10:20:00+00:00",
      "sources": ["172.16.0.1"],
      "targets": ["192.168.10.50"]
    }
  ]
}
```

A timestamp with no offset is read as UTC, and the tool says so rather than
guessing a local zone. `docs/examples/schedule.template.json` is a starting
point.

### Two denominators, reported apart

- **finding precision** — of the findings raised, how many landed inside a
  labelled window *attributed to that source*. Requiring the source to match
  matters: without it, any finding during a busy attack window scores as a
  catch.
- **window recall** — of the labelled windows, how many produced at least one
  finding. A window is caught or missed; ten findings inside it is still one
  window caught.

These are deliberately not folded into a single number.

## Working with the public datasets

> Attack schedules below must be transcribed from each dataset's own
> documentation. This repository does not ship them, because a schedule
> reproduced from memory would silently corrupt every number computed with it.

**CIC-IDS2017 / CSE-CIC-IDS2018.** Use the **raw PCAPs**, not the bundled
CSVs. Those CSVs are CICFlowMeter output — *bidirectional* flow records — and
NEMOS aggregates unidirectional flows by design, so the CSVs are the wrong
input shape. They remain useful as a *label source*: each row carries a source,
a destination, a timestamp and a class, so per-class time ranges and address
sets can be rolled up into the schedule format above. Budget ~8–13 GB per day
file and use `--limit` to sanity-check a prefix before committing to a full run.

**UNSW-NB15.** Ships raw PCAPs alongside a ground-truth file giving attack
categories with start and stop times, which maps onto the schedule format
directly.

**MACCDC.** Unlabelled. Use it for the parse report — question 1 — not for
precision and recall.

## What this still does not measure

- **The ML layer.** These are the deterministic rules. The Isolation Forest is
  not exercised by this path.
- **Your network.** A public capture is somebody else's traffic. The last step
  is a mirror port on a network you are authorised to monitor.
- **Evasion.** Nothing here is paced to slip under a window on purpose; see
  `nemos/slowscan.py` for the tier that addresses that, which this does not
  score.
