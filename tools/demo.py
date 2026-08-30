#!/usr/bin/env python3
"""End-to-end NEMOS demonstration on controlled synthetic traffic.

Runs the complete pipeline in one process and prints what each stage produced:

    synthetic traffic -> unidirectional flows -> features -> ML + baseline
        -> deterministic rules -> fusion -> incident -> storage

Everything is generated in memory using RFC 5737 documentation addresses. No
packet is transmitted, no interface is touched and no host is contacted. Nothing
here is an attack tool -- the "scan" scenarios are lists of synthetic metadata
records that never leave the process.

Usage::

    python tools/demo.py                  # all scenarios
    python tools/demo.py --scenario port_sweep
    python tools/demo.py --json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from scenarios import ATTACK_SCENARIOS, SCENARIOS, build  # noqa: E402

from nemos.analysis import AnalysisEngine  # noqa: E402
from nemos.detector import DetectionConfig, ThreatDetector  # noqa: E402
from nemos.ml import sklearn_available  # noqa: E402

BAR = "=" * 78


def _run_scenario(name: str, model_dir: Path, window: float) -> dict:
    """Push one scenario through the full pipeline and collect the results."""
    scenario = build(name)
    detector = ThreatDetector(DetectionConfig.from_env())
    emitted: list = []
    persisted: list = []

    engine = AnalysisEngine(
        model_dir=model_dir,
        window_seconds=window,
        on_alert=emitted.append,
        on_flows=lambda flows: persisted.extend(f.as_dict() for f in flows),
        anomaly_cooldown=0.0,
    )
    engine.model.load()

    # Step through time in window-sized increments, exactly as the running
    # sensor does. Collapsing a whole scenario into one window would inflate
    # every rate by the ratio of scenario length to window length and
    # manufacture findings that the real pipeline would never produce.
    rule_alerts = []
    windows = []
    boundary = window
    for offset, event in scenario.events:
        while offset >= boundary:
            completed = engine.run_cycle(now=boundary, force=True)
            if completed is not None:
                windows.append(completed)
            boundary += window
        engine.observe(event)                                   # flow aggregation
        for alert in detector.process(event, event.protocol, now=offset):  # rules, simulated clock
            rule_alerts.append(alert)
            engine.record_rule_alerts(event.source, [alert])
    final = engine.run_cycle(now=boundary, force=True)
    if final is not None:
        windows.append(final)

    assessments = [a for w in windows for a in w.assessments]
    actionable = [a for a in assessments if a.actionable]
    # Report the most severe window, which is what an analyst would triage.
    actionable.sort(key=lambda a: a.risk_score, reverse=True)
    return {
        "scenario": scenario.name,
        "description": scenario.description,
        "expectation": scenario.expectation,
        "events": len(scenario),
        "windows": len(windows),
        "flows": len(persisted),
        "sources": max((w.sources for w in windows), default=0),
        "scored_by_model": sum(w.scored_by_model for w in windows),
        "rule_alerts": [
            {"threat": a.threat, "risk": a.risk_score, "technique": a.technique,
             "reason": a.reason}
            for a in rule_alerts
        ],
        "assessments": [a.as_dict() for a in actionable],
        "statistical_alerts": [
            {"threat": a.threat, "severity": a.severity, "risk": a.risk_score,
             "confidence": a.confidence, "reason": a.reason}
            for a in emitted
        ],
    }


def _print_scenario(result: dict) -> None:
    print(f"\n{BAR}\n{result['scenario'].upper()}\n{BAR}")
    print(f"  {result['description']}")
    print(f"  expected: {result['expectation']}")
    print(f"\n  pipeline: {result['events']} events -> {result['flows']} unidirectional flows "
          f"-> {result['windows']} window(s) -> {result['sources']} source(s) "
          f"-> {result['scored_by_model']} scored by model")

    rules = result["rule_alerts"]
    if rules:
        seen = {}
        for alert in rules:
            seen.setdefault(alert["threat"], alert)
        print(f"\n  deterministic rules ({len(rules)} alert(s), {len(seen)} distinct):")
        for threat, alert in seen.items():
            technique = alert["technique"] or "unmapped"
            print(f"    - {threat:26s} risk={alert['risk']:3d}  ATT&CK={technique}")
            print(f"      {alert['reason']}")
    else:
        print("\n  deterministic rules: no finding")

    for assessment in result["assessments"]:
        print(f"\n  fused assessment for {assessment['source']}:")
        print(f"    verdict:     {assessment['verdict']}")
        print(f"    risk:        {assessment['risk_score']}/100  ({assessment['severity']})")
        print(f"    confidence:  {assessment['confidence']}%")
        print(f"    anomaly:     {assessment['anomaly_score']}")
        print(f"    baseline:    {assessment['baseline_state']}")
        print(f"    layers:      {', '.join(assessment['detection_layers'])}")
        print(f"    ATT&CK:      {', '.join(assessment['techniques']) or 'none (not evidenced)'}")
        explanation = assessment["explanation"]
        print(f"    arithmetic:  {explanation['rule_floor']} (rules) "
              f"+ {explanation['ml_contribution']} (ml) "
              f"+ {explanation['baseline_contribution']} (baseline) "
              f"+ {explanation['corroboration_bonus']} (corroboration) "
              f"= {explanation['subtotal']}, capped at {explanation['ceiling']}")
        if assessment["reasons"]:
            print("    evidence:")
            for reason in assessment["reasons"][:5]:
                print(f"      - {reason}")

    if not result["assessments"]:
        print("\n  fused assessment: nothing actionable (as expected for normal traffic)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS),
                        help="run one scenario instead of all")
    parser.add_argument("--model-dir", type=Path,
                        help="use an existing model instead of training a temporary one")
    parser.add_argument("--window", type=float, default=10.0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-train", action="store_true",
                        help="skip training; shows the rules-only degraded path")
    args = parser.parse_args(argv)

    names = [args.scenario] if args.scenario else ["normal", *ATTACK_SCENARIOS]

    with tempfile.TemporaryDirectory() as td:
        model_dir = args.model_dir or Path(td)
        trained = False

        if not args.no_train and args.model_dir is None:
            if not sklearn_available():
                if not args.json:
                    print("scikit-learn is not installed: running with deterministic\n"
                          "rules and the statistical baseline only. This is a supported\n"
                          "configuration, not a failure.\n")
            else:
                if not args.json:
                    print("Training a temporary model on synthetic normal traffic...")
                from train_model import load_synthetic

                from nemos.ml import AnomalyEngine
                vectors = load_synthetic(args.window, 240)
                report = AnomalyEngine(model_dir).train(vectors)
                trained = True
                if not args.json:
                    print(f"  {report.samples} windows, {report.features} features, "
                          f"scikit-learn {report.sklearn_version}\n")

        results = [_run_scenario(name, model_dir, args.window) for name in names]

    if args.json:
        print(json.dumps({"model_trained": trained, "scenarios": results}, indent=2))
        return 0

    for result in results:
        _print_scenario(result)

    print(f"\n{BAR}\nSUMMARY\n{BAR}")
    print(f"  {'scenario':22s} {'flows':>6s} {'win':>4s} {'rules':>6s} {'anomaly':>8s} {'risk':>5s}  verdict")
    for result in results:
        assessment = result["assessments"][0] if result["assessments"] else None
        distinct_rules = len({a["threat"] for a in result["rule_alerts"]})
        print(f"  {result['scenario']:22s} {result['flows']:6d} {result['windows']:4d} {distinct_rules:6d} "
              f"{str(assessment['anomaly_score']) if assessment else '-':>8s} "
              f"{assessment['risk_score'] if assessment else 0:5d}  "
              f"{assessment['verdict'] if assessment else 'NO_FINDING'}")
    print("\n  All traffic was synthetic and confined to this process.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
