# Soak test

Every hot-path structure in NEMOS is bounded *by design* — eviction appears
throughout `detector.py`, `flows.py`, `behavioral.py` and `slowscan.py`.
Bounded by design and bounded in practice are different claims, and only one of
them has evidence. `tools/soak.py` produces the evidence.

```bash
python tools/soak.py --minutes 60 --rate 0.15 --json soak.json
```

It starts a real sensor, drives it with continuous **loopback-only** traffic,
and samples what would grow if a bound were wrong. Nothing leaves the machine.

Growth is fitted **after a warm-up period** (`--warmup`, 300s by default). A
process fills caches, bootstraps the ML sample buffer and opens its database in
the first minutes; extrapolating that slope to an hour reports a leak that is
not there.

## Results — 60 minutes, 120 samples, 29,809 packets

| Measure | Start | End | Verdict |
| --- | ---: | ---: | --- |
| RSS | 179.7 MB | 193.2 MB | **decelerating**, see below |
| Threads | 19 | 19 | **flat** — no thread leak |
| Open file descriptors | 15 | 16 (peak 17) | **bounded** |
| Database | 0.12 MB | 7.7 MB | growing; retention not yet engaged |
| Queue high-water | — | 160 of 50,000 | never close to backpressure |
| Dropped alerts | — | 0 | |
| Write errors | — | 0 | |
| API errors | — | 0 | |

### Memory is decelerating, not flat

Splitting the post-warm-up samples in half:

| Window | RSS trend |
| --- | ---: |
| First half after warm-up | +15.2 MB/hour |
| Second half | +9.1 MB/hour |

Per ten minutes the deltas were +4.0, +2.5, +2.2, +1.7, +1.3, +1.3 MB — a curve
approaching a bound rather than a straight line, which is what bounded buffers
filling looks like. **It is not proven flat.** Sixty minutes was not long enough
to reach the asymptote, and the honest statement is "decelerating toward a
bound, not yet observed to plateau". A multi-hour run is the way to settle it.

### Database growth is retention that has not engaged yet

`NEMOS_MAX_TRAFFIC` defaults to 100,000 rows. The run ended with **29,819
traffic rows**, 5,893 flows and 128 alerts — the cap had not been reached, so
nothing had been pruned and the file grew linearly at ~7 MB/hour. That is
pre-cap fill, not unbounded growth.

Projecting from the observed row size, the file should plateau in the tens of
megabytes once retention starts pruning. **That projection is arithmetic, not a
measurement** — confirming it needs a run long enough to cross the cap.

### The sensor did not always keep up

39 of 120 samples reported `DEGRADED`, spread across the whole hour rather than
only at startup. At this offered load on loopback, NEMOS intermittently could
not drain the capture socket fast enough.

This is the drop accounting doing its job, and it is the honest reading: the
sensor says so instead of reporting `ONLINE` while losing packets. Loopback is
also an unusually harsh source — there is no NIC pacing between the generator
and the capture socket.

## Picking a rate

`--rate` scales the offered load. Lower it until the sensor stays `ONLINE`
after warm-up: a saturated sensor measures overload behaviour, which is a
different and also useful test, but it is not a leak test. The first run of this
harness saturated the sensor at the default rate and reported a memory slope
that was really warm-up plus queue pressure.
