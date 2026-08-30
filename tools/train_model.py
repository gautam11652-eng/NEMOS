#!/usr/bin/env python3
"""Train the NEMOS anomaly-detection model.

Training is deliberately an explicit, out-of-band operator action rather than
something the sensor does on its own. A model that retrained itself on live
traffic would learn to accept whatever it is currently seeing -- including an
attack in progress.

Two sources of training data:

``--source database`` (default)
    Replays traffic already captured into ``data/nemos.db``. This is what you
    want for a real deployment: the model learns *your* network's normal, not a
    generic idea of normal. Capture a representative period first -- ideally
    covering a full daily cycle -- and be reasonably confident it is clean.

``--source synthetic``
    Generates synthetic RFC 5737 documentation traffic in memory. Use this to
    evaluate the pipeline, run the demonstration, or produce a model on a
    machine that has never captured anything. A model trained this way tells you
    the system works; it says nothing about your network.

Examples::

    python tools/train_model.py --source synthetic
    python tools/train_model.py --source database --window 10
    python tools/train_model.py --source database --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nemos.database import connect  # noqa: E402
from nemos.features import FEATURE_NAMES, FeatureVector, extract_all  # noqa: E402
from nemos.flows import FlowTable, group_by_source  # noqa: E402
from nemos.ml import AnomalyEngine, InsufficientTrainingData, MIN_TRAINING_SAMPLES, sklearn_available  # noqa: E402
from nemos.models import TrafficEvent  # noqa: E402

log = logging.getLogger("nemos.train")


def _parse_timestamp(value: str) -> float | None:
    """Parse a stored ISO-8601 timestamp into epoch seconds."""
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return None


def windows_from_events(events: list[tuple[float, TrafficEvent]],
                        window_seconds: float) -> list[FeatureVector]:
    """Bucket time-ordered events into fixed windows and extract features.

    Each window gets its own flow table: a flow does not span windows, so a
    window's features describe only what happened inside it.
    """
    if not events:
        return []
    events.sort(key=lambda item: item[0])
    origin = events[0][0]
    vectors: list[FeatureVector] = []
    bucket: list[tuple[float, TrafficEvent]] = []
    index = 0

    for offset, event in events:
        while offset >= origin + (index + 1) * window_seconds:
            vectors.extend(_vectors_for(bucket, window_seconds))
            bucket = []
            index += 1
        bucket.append((offset, event))
    vectors.extend(_vectors_for(bucket, window_seconds))
    return vectors


def _vectors_for(bucket: list[tuple[float, TrafficEvent]], window_seconds: float) -> list[FeatureVector]:
    if not bucket:
        return []
    table = FlowTable(idle_timeout=window_seconds * 10, max_duration=window_seconds * 10)
    for offset, event in bucket:
        table.observe(event, now=offset)
    return extract_all(group_by_source(table.snapshot()), window_seconds)


def load_from_database(db_path: Path, window_seconds: float, limit: int) -> list[FeatureVector]:
    """Replay stored traffic rows into windowed feature vectors."""
    if not db_path.is_file():
        raise FileNotFoundError(
            f"no database at {db_path}. Run NEMOS with capture enabled first, "
            f"or train with --source synthetic."
        )
    connection = connect(db_path)
    try:
        rows = connection.execute(
            """SELECT timestamp, source, destination, source_port, destination_port,
                      protocol, packet_size, flags, interface
               FROM traffic ORDER BY id ASC LIMIT ?""",
            (limit,),
        ).fetchall()
    finally:
        connection.close()

    events: list[tuple[float, TrafficEvent]] = []
    skipped = 0
    for row in rows:
        epoch = _parse_timestamp(row["timestamp"])
        if epoch is None:
            skipped += 1
            continue
        events.append((epoch, TrafficEvent(
            row["timestamp"], row["source"], row["destination"], row["protocol"],
            row["source_port"], row["destination_port"], int(row["packet_size"] or 0),
            row["flags"] or "", row["interface"] or "",
        )))
    if skipped:
        log.warning("skipped %d row(s) with an unparseable timestamp", skipped)
    log.info("loaded %d traffic row(s) from %s", len(events), db_path)
    return windows_from_events(events, window_seconds)


def load_synthetic(window_seconds: float, windows: int) -> list[FeatureVector]:
    """Generate training vectors from synthetic normal traffic."""
    from scenarios import training_corpus

    vectors: list[FeatureVector] = []
    for scenario in training_corpus(windows=windows, window_seconds=window_seconds):
        vectors.extend(windows_from_events(list(scenario.events), window_seconds))
    log.info("generated %d synthetic feature window(s)", len(vectors))
    return vectors


def summarize(vectors: list[FeatureVector]) -> dict:
    """Report the shape of the training data before fitting anything to it."""
    if not vectors:
        return {"windows": 0}
    sources = {v.source for v in vectors}
    summary = {"windows": len(vectors), "unique_sources": len(sources), "features": {}}
    for index, name in enumerate(FEATURE_NAMES):
        column = sorted(v.values[index] for v in vectors)
        summary["features"][name] = {
            "min": round(column[0], 3),
            "median": round(column[len(column) // 2], 3),
            "max": round(column[-1], 3),
        }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Train the NEMOS anomaly-detection model.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--source", choices=("database", "synthetic"), default="database",
                        help="where training data comes from (default: database)")
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "nemos.db",
                        help="SQLite path for --source database")
    parser.add_argument("--model-dir", type=Path, default=ROOT / "data" / "model",
                        help="where the trained model is written")
    parser.add_argument("--window", type=float, default=10.0,
                        help="aggregation window in seconds (default: 10)")
    parser.add_argument("--limit", type=int, default=500_000,
                        help="maximum traffic rows to read from the database")
    parser.add_argument("--synthetic-windows", type=int, default=240,
                        help="number of synthetic windows for --source synthetic")
    parser.add_argument("--estimators", type=int, default=200,
                        help="number of trees in the Isolation Forest")
    parser.add_argument("--contamination", default="auto",
                        help="'auto' or a float in (0, 0.5]")
    parser.add_argument("--dry-run", action="store_true",
                        help="summarize the training data without fitting a model")
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s | %(message)s",
    )

    if not sklearn_available() and not args.dry_run:
        print(
            "scikit-learn is not installed, so a model cannot be trained.\n"
            "  pip install -r requirements.txt\n\n"
            "NEMOS runs without it -- deterministic rules and the statistical\n"
            "baseline are unaffected; only ML anomaly scoring is unavailable.",
            file=sys.stderr,
        )
        return 2

    contamination: str | float = args.contamination
    if contamination != "auto":
        try:
            contamination = float(contamination)
        except ValueError:
            print(f"invalid --contamination: {args.contamination}", file=sys.stderr)
            return 2
        if not 0.0 < contamination <= 0.5:
            print("--contamination must be 'auto' or in (0, 0.5]", file=sys.stderr)
            return 2

    try:
        if args.source == "database":
            vectors = load_from_database(args.db, args.window, args.limit)
        else:
            vectors = load_synthetic(args.window, args.synthetic_windows)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    summary = summarize(vectors)
    if args.dry_run:
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            print(f"training windows: {summary.get('windows', 0)}")
            print(f"unique sources:   {summary.get('unique_sources', 0)}")
            print(f"minimum required: {MIN_TRAINING_SAMPLES}")
            if summary.get("windows", 0) < MIN_TRAINING_SAMPLES:
                print("\nNot enough data to train. Capture more traffic, or use a shorter --window.")
        return 0

    engine = AnomalyEngine(args.model_dir)
    try:
        report = engine.train(vectors, contamination=contamination, n_estimators=args.estimators)
    except InsufficientTrainingData as exc:
        print(f"{exc}", file=sys.stderr)
        return 3
    except (RuntimeError, ValueError) as exc:
        print(f"training failed: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"training": report.as_dict(), "data": summary}, indent=2))
    else:
        print("Model trained.")
        print(f"  samples:        {report.samples} windows")
        print(f"  features:       {report.features} (schema v{report.schema_version})")
        print(f"  model version:  {report.model_version}")
        print(f"  scikit-learn:   {report.sklearn_version}")
        print(f"  written to:     {engine.model_path}")
        print("\nNEMOS loads this automatically on the next start.")
        if args.source == "synthetic":
            print(
                "\nNote: this model was fitted on synthetic traffic. It demonstrates the\n"
                "pipeline but does not describe your network. Retrain with\n"
                "--source database once you have captured representative traffic."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
