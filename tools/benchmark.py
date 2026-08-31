#!/usr/bin/env python3
"""Reproducible capture-path benchmark.

Every performance number in the documentation comes from this script, so any
reader can check the claim on their own hardware rather than trusting it:

    python tools/benchmark.py

Why it reports a range rather than a single figure
--------------------------------------------------
Detection cost is dominated by how many events sit in a source's window, not by
the packet rate. A handful of busy hosts fill their windows to ``max_events``
and cost the most per packet; a spoofing flood spreads packets across thousands
of short-lived windows and costs less each. Quoting only the fast case would
overstate what the sensor does on a small, busy LAN -- which is the common
deployment.

All traffic is synthetic, generated in memory, and confined to this process.
Nothing is transmitted and no interface is touched.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nemos.detector import DetectionConfig, ThreatDetector  # noqa: E402
from nemos.models import TrafficEvent  # noqa: E402

PROFILES = (
    ("small LAN", 50, "a few busy hosts; windows fill to max_events"),
    ("office", 500, "typical mixed workload"),
    ("large segment", 5_000, "many hosts, shorter windows each"),
    ("spoofing flood", 50_000, "adversarial: a new source almost every packet"),
)


def synthesise(sources: int, count: int, seed: int = 7) -> list[TrafficEvent]:
    """Build traffic spread over ``sources`` distinct addresses."""
    rng = random.Random(seed)
    events = []
    for i in range(count):
        host = i % sources
        events.append(TrafficEvent(
            "2026-01-01T00:00:00Z",
            f"10.{host // 65536 % 256}.{host // 256 % 256}.{host % 256}",
            f"203.0.113.{i % 250}",
            "TCP", 40000, rng.choice([80, 443, 22, 445]),
            rng.randint(60, 1400), "S",
        ))
    return events


def measure(sources: int, count: int, repeats: int) -> tuple[float, float]:
    """Return (packets per second, microseconds per packet), best of repeats.

    Best-of rather than mean: the slowest runs measure the machine's other
    load, not the detector.
    """
    rates = []
    for _ in range(repeats):
        detector = ThreatDetector(DetectionConfig())
        events = synthesise(sources, count)
        start = time.perf_counter()
        for index, event in enumerate(events):
            detector.process(event, "TCP", now=1000.0 + index * 0.001)
        elapsed = time.perf_counter() - start
        rates.append(count / elapsed)
    best = max(rates)
    return best, 1e6 / best


def bounded_state(packets: int = 60_000) -> list[tuple[str, int, int, bool]]:
    """Confirm every attacker-keyed map stays inside its bound under a flood."""
    detector = ThreatDetector(DetectionConfig(max_sources=256))
    for index in range(packets):
        detector.process(TrafficEvent(
            "2026-01-01T00:00:00Z",
            f"10.{index % 250}.{index % 250}.{index % 250}",
            f"203.0.113.{index % 250}", "TCP", 40000, 8443, 200, "S",
        ), "TCP", now=1000.0 + index * 0.01)
    limit = detector.cfg.max_sources
    rows = [
        ("event windows", len(detector.events), limit),
        ("behaviour profiles", len(detector.behavior._profiles), limit),
        ("incidents", len(detector.incidents), limit),
        ("alert cooldowns", len(detector.last), limit * 16),
        ("contact history", len(detector.contacts), limit * 4),
        ("beacon targets", len(detector.beacon_targets), limit * 4),
        ("address memo", len(detector._private_cache), 8192),
    ]
    return [(name, size, bound, size <= bound) for name, size, bound in rows]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--packets", type=int, default=20_000,
                        help="packets per profile (default: 20000)")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--skip-bounds", action="store_true")
    args = parser.parse_args()

    print("NEMOS capture-path benchmark")
    print(f"python {sys.version.split()[0]} | {args.packets:,} packets per profile "
          f"| best of {args.repeats}\n")
    print(f"  {'profile':16} {'sources':>8} {'packets/sec':>13} {'us/packet':>11}   note")
    print(f"  {'-' * 16} {'-' * 8} {'-' * 13} {'-' * 11}   {'-' * 40}")

    results = []
    for name, sources, note in PROFILES:
        rate, per_packet = measure(sources, args.packets, args.repeats)
        results.append((name, rate, per_packet))
        print(f"  {name:16} {sources:>8,} {rate:>13,.0f} {per_packet:>11.1f}   {note}")

    slowest = min(r for _, r, _ in results)
    fastest = max(r for _, r, _ in results)
    print(f"\n  Range: {slowest:,.0f} - {fastest:,.0f} packets/sec.")
    print("  Cost is driven by window occupancy, so the small-LAN figure is the")
    print("  one to plan capacity against, not the fastest.")
    print("\n  Per-packet cost is linear in window size: every rule reads from a")
    print("  single aggregate, but that aggregate is still derived by one pass")
    print("  over the window. Removing the linearity needs incremental counters")
    print("  maintained on append and eviction, which NEMOS does not do today.")

    if not args.skip_bounds:
        print("\n  Bounded state under a spoofing flood (max_sources=256):")
        rows = bounded_state()
        for name, size, bound, held in rows:
            print(f"    {'ok ' if held else 'LEAK'} {name:20} {size:>6,} <= {bound:,}")
        if not all(held for *_, held in rows):
            return 1

    print("\n  All traffic was synthetic and confined to this process.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
