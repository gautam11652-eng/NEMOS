#!/usr/bin/env python3
"""Measure how well NEMOS detects, not how fast it runs.

``tools/benchmark.py`` answers "how many packets per second". This answers the
question that actually decides whether a detector is worth deploying: when
something happens, does it notice, and how often does it cry wolf.

    python tools/benchmark_detection.py
    python tools/benchmark_detection.py --json results.json
    python tools/benchmark_detection.py --repeats 20

All traffic is synthetic, generated in memory from RFC 5737 documentation
addresses. Nothing is transmitted, no interface is touched and no host is
contacted.

How the score is computed
-------------------------
Every scenario in ``tools/scenarios.py`` carries machine-readable ground truth
(``Scenario.expected``) decided from the *traffic shape*, independently of what
the detector happens to emit. That independence is the whole point: labelling
scenarios with whatever NEMOS already finds would make recall 1.0 by
construction and measure nothing.

Per replay of a malicious scenario:

- **true positive** -- at least one finding from the expected set fired
- **false negative** -- none did
- **misattribution** -- findings fired, but none from the expected set. Counted
  as a false negative *and* reported separately, because "detected the wrong
  thing" and "detected nothing" are different failures with different fixes.

Per replay of a benign scenario, every finding is a **false positive**. Benign
replays are also the true-negative population: a clean replay is one true
negative.

Detection latency is measured in scenario seconds -- the detector's clock is
driven by each event's own offset -- so it is the delay a real deployment would
see, not an artefact of replaying an hour of traffic in a second.

Repeats vary the generator seed, so each figure is an average over independent
traffic rather than one lucky draw.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from nemos.detector import DetectionConfig, ThreatDetector  # noqa: E402
from nemos.version import VERSION  # noqa: E402
from scenarios import SCENARIOS, build  # noqa: E402


@dataclass
class Counts:
    """Confusion-matrix cells for one detection type, or overall.

    False positives are split into two populations, because folding them
    together would misreport in both directions.

    ``false_positive`` is the unambiguous kind: the finding fired on benign
    traffic, where the correct answer was silence. This is the cry-wolf number
    and it is what precision is computed from.

    ``fired_elsewhere`` is a finding that appeared on *malicious* traffic
    labelled as something else -- PORT_SCAN on a UDP sweep, NETWORK_FANOUT on an
    ICMP sweep. Calling that a false positive would be unfair: the traffic
    really was suspicious and the finding is arguably a second correct reading.
    Ignoring it would be too kind, since it would let a detector spray every
    label at every attack for free. So it is counted, reported in its own
    column, and deliberately kept out of precision.
    """

    true_positive: int = 0
    false_positive: int = 0
    fired_elsewhere: int = 0
    false_negative: int = 0
    true_negative: int = 0

    @property
    def precision(self) -> float | None:
        """Of what it flagged on benign traffic, how much was right.

        None rather than 0.0 when it never fired: a detector that has not been
        asked has undefined precision, and 0.00 would read as "always wrong".
        """
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else None

    @property
    def recall(self) -> float | None:
        """Of what was there, how much it caught."""
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else None

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    def as_dict(self) -> dict[str, Any]:
        return {
            "true_positive": self.true_positive,
            "false_positive_benign": self.false_positive,
            "fired_on_other_malicious": self.fired_elsewhere,
            "false_negative": self.false_negative,
            "true_negative": self.true_negative,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


@dataclass
class ScenarioResult:
    name: str
    expected: tuple[str, ...]
    benign: bool
    replays: int = 0
    detected: int = 0
    misattributed: int = 0
    findings: dict[str, int] = field(default_factory=dict)
    latencies: list[float] = field(default_factory=list)

    @property
    def detection_rate(self) -> float | None:
        if self.benign or not self.replays:
            return None
        return self.detected / self.replays

    @property
    def median_latency(self) -> float | None:
        return statistics.median(self.latencies) if self.latencies else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.name,
            "expected": list(self.expected),
            "benign": self.benign,
            "replays": self.replays,
            "detected": self.detected,
            "misattributed": self.misattributed,
            "detection_rate": self.detection_rate,
            "median_latency_seconds": self.median_latency,
            "findings": dict(sorted(self.findings.items())),
        }


def replay(scenario, config: DetectionConfig) -> list[tuple[float, str]]:
    """Run one scenario through a fresh detector. Returns (offset, threat) pairs.

    A fresh detector per replay is deliberate: cooldown and incident state carry
    across findings, so a shared instance would let one scenario suppress the
    next and quietly inflate the false-negative count of whichever ran later.

    The detector's clock is driven by each event's own offset, so a window means
    simulated seconds. Without that, replaying ten seconds of traffic in three
    milliseconds puts every event in one window and manufactures findings that a
    real deployment would never see.
    """
    detector = ThreatDetector(config)
    fired: list[tuple[float, str]] = []
    for offset, event in scenario.events:
        for alert in detector.process(event, event.protocol, now=offset):
            fired.append((offset, alert.threat))
    return fired


def evaluate(repeats: int, config: DetectionConfig) -> dict[str, Any]:
    results: dict[str, ScenarioResult] = {}
    per_type: dict[str, Counts] = {}
    overall = Counts()
    started = time.monotonic()

    for name in SCENARIOS:
        probe = build(name)
        result = ScenarioResult(name, probe.expected, probe.benign)
        results[name] = result

        for index in range(repeats):
            # A different seed each replay: one draw of pseudo-random traffic is
            # an anecdote, not a measurement.
            scenario = build(name, seed=1000 + index)
            fired = replay(scenario, config)
            result.replays += 1

            names = {threat for _, threat in fired}
            for threat in names:
                result.findings[threat] = result.findings.get(threat, 0) + 1

            if scenario.benign:
                # Every finding on benign traffic is a false positive; a clean
                # replay is one true negative.
                overall.false_positive += len(names)
                for threat in names:
                    per_type.setdefault(threat, Counts()).false_positive += 1
                if not names:
                    overall.true_negative += 1
                continue

            hits = names & set(scenario.expected)
            if hits:
                result.detected += 1
                overall.true_positive += 1
                first = min(offset for offset, threat in fired if threat in hits)
                result.latencies.append(first)
            else:
                overall.false_negative += 1
                if names:
                    result.misattributed += 1

            # `expected` is a set of acceptable answers, not a checklist. Each
            # member that fired is a true positive; a member that did not is
            # *not* a miss, because another member covering the same shape was
            # an equally correct reading. Charging every unfired alternative an
            # FN reported LATERAL_MOVEMENT and DNS_TUNNELING_PATTERN at 0%
            # recall for shapes they were never required to catch.
            for threat in scenario.expected:
                if threat in names:
                    per_type.setdefault(threat, Counts()).true_positive += 1
            if not hits:
                # Nothing acceptable fired. The miss is charged once, to the
                # primary label, rather than smeared across the alternatives.
                per_type.setdefault(scenario.expected[0], Counts()).false_negative += 1
            # Fired on malicious traffic labelled as something else. Not a false
            # positive -- the traffic was genuinely suspicious -- but tracked so
            # a detector cannot spray every label at every attack for free.
            for threat in names - set(scenario.expected):
                per_type.setdefault(threat, Counts()).fired_elsewhere += 1

    benign_replays = sum(r.replays for r in results.values() if r.benign)
    latencies = [value for r in results.values() for value in r.latencies]
    return {
        "nemos_version": VERSION,
        "python": sys.version.split()[0],
        "repeats": repeats,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "window_seconds": config.window,
        "min_confidence": config.min_confidence,
        "overall": overall.as_dict(),
        "false_positives_per_benign_replay": (
            overall.false_positive / benign_replays if benign_replays else None
        ),
        "median_latency_seconds": statistics.median(latencies) if latencies else None,
        "per_detection": {
            name: counts.as_dict() for name, counts in sorted(per_type.items())
        },
        "per_scenario": [results[name].as_dict() for name in SCENARIOS],
    }


def _pct(value: float | None) -> str:
    return "     —" if value is None else f"{value * 100:5.1f}%"


def _num(value: float | None, suffix: str = "") -> str:
    return "    —" if value is None else f"{value:5.2f}{suffix}"


def report(data: dict[str, Any]) -> None:
    overall = data["overall"]
    print("NEMOS detection benchmark")
    print(f"  nemos {data['nemos_version']} | python {data['python']} | "
          f"{data['repeats']} replays per scenario | {data['elapsed_seconds']}s")
    print(f"  window {data['window_seconds']}s | confidence floor "
          f"{data['min_confidence']}")
    print()

    print(f"  {'detection':28} {'prec':>7} {'recall':>7} {'F1':>7} "
          f"{'TP':>4} {'FN':>4} {'FP':>4} {'else':>5}")
    print(f"  {'-' * 28} {'-' * 7} {'-' * 7} {'-' * 7} {'-' * 4} {'-' * 4} "
          f"{'-' * 4} {'-' * 5}")
    for name, counts in data["per_detection"].items():
        print(f"  {name:28} {_pct(counts['precision'])} {_pct(counts['recall'])} "
              f"{_pct(counts['f1'])} {counts['true_positive']:>4} "
              f"{counts['false_negative']:>4} {counts['false_positive_benign']:>4} "
              f"{counts['fired_on_other_malicious']:>5}")
    print()

    print(f"  {'scenario':22} {'rate':>7} {'latency':>9}   findings")
    print(f"  {'-' * 22} {'-' * 7} {'-' * 9}   {'-' * 40}")
    for item in data["per_scenario"]:
        found = ", ".join(f"{k}×{v}" for k, v in item["findings"].items()) or "none"
        label = "benign" if item["benign"] else _pct(item["detection_rate"])
        print(f"  {item['scenario']:22} {label:>7} "
              f"{_num(item['median_latency_seconds'], 's'):>9}   {found[:60]}")
        if item["misattributed"]:
            print(f"  {'':22} {'':7} {'':9}   "
                  f"!! {item['misattributed']} replay(s) detected something, "
                  f"none of it expected")
    print()

    print(f"  Overall precision {_pct(overall['precision'])}  "
          f"recall {_pct(overall['recall'])}  F1 {_pct(overall['f1'])}")
    print(f"  True negatives: {overall['true_negative']} clean benign replays")
    fp_rate = data["false_positives_per_benign_replay"]
    print(f"  False positives on benign traffic: {_num(fp_rate)} per replay")
    print(f"  Median detection latency: "
          f"{_num(data['median_latency_seconds'], 's')} of scenario time")
    print()
    print("  FP counts firings on benign traffic, where silence was correct, and is\n"
          "  what precision is computed from. `else` counts firings on malicious\n"
          "  traffic labelled as something else -- suspicious traffic read a second\n"
          "  valid way -- which is tracked but deliberately kept out of precision.")
    print()
    print("  Ground truth is the traffic shape, set in tools/scenarios.py "
          "independently\n  of what the detector emits. All traffic was "
          "synthetic and never left this\n  process.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--repeats", type=int, default=10,
                        help="replays per scenario, each with a different seed")
    parser.add_argument("--json", metavar="PATH",
                        help="also write machine-readable results here")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the table; useful with --json")
    args = parser.parse_args()

    repeats = max(1, min(200, args.repeats))
    data = evaluate(repeats, DetectionConfig.from_env())

    if not args.quiet:
        report(data)
    if args.json:
        path = Path(args.json)
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
        if not args.quiet:
            print(f"\n  Machine-readable results written to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
