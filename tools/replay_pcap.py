#!/usr/bin/env python3
"""Replay a capture file through the real NEMOS detection path.

This answers two questions ``tools/benchmark_detection.py`` cannot, because its
corpus is synthetic:

1. **Does the parsing layer survive real packets?** Production captures carry
   truncated headers, VLAN tags, tunnels, bad checksums and link types a
   generator never produces. Anything that raises is counted and reported
   rather than silently dropped -- a parser that skips 3% of a capture and says
   nothing is worse than one that crashes.
2. **What does NEMOS detect on labelled traffic?** Given an attack schedule,
   every finding is scored against ground truth.

Two properties keep the numbers honest:

* **The parser is the live one.** ``PacketCapture._parse`` and ``_parse_arp``
  are called directly, so what is measured here is what runs on a live socket.
* **The clock comes from the packets.** The detector's window is driven by each
  packet's own recorded time, not by how fast the file is read. Stamping an
  hour-long capture with "now" would put every packet inside one window and
  manufacture findings.

Nothing here transmits. It opens a file.

    python tools/replay_pcap.py capture.pcap
    python tools/replay_pcap.py capture.pcap --labels schedule.json
    python tools/replay_pcap.py capture.pcap --limit 2000000 --json out.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nemos.capture import PacketCapture  # noqa: E402
from nemos.detector import DetectionConfig, ThreatDetector  # noqa: E402
from nemos.version import VERSION  # noqa: E402

# A capture file is not guaranteed to be time-ordered, and the detector's
# windows assume a clock that does not run backwards. A handful of inversions
# is normal on a multi-interface capture; a flood of them means the file needs
# sorting first, so the count is reported rather than hidden.
REORDER_TOLERANCE = 0.0


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def read(path: Path, stats: Counter, limit: int | None = None):
    """Stream ``(epoch, TrafficEvent, ptype)`` out of a capture file.

    Streamed with PcapReader rather than rdpcap: a CIC-IDS day file is several
    gigabytes and rdpcap would hold all of it in memory at once.
    """
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, PcapReader, TCP, UDP

    previous = None
    with PcapReader(str(path)) as reader:
        for index, packet in enumerate(reader):
            if limit is not None and index >= limit:
                stats["truncated_by_limit"] = 1
                break
            stats["read"] += 1
            try:
                when = float(packet.time)
            except Exception:
                stats["no_timestamp"] += 1
                continue
            if previous is not None and when < previous - REORDER_TOLERANCE:
                stats["out_of_order"] += 1
            previous = when

            stamp = iso(when)
            try:
                event, ptype = PacketCapture._parse_arp(packet, ARP, "", stamp)
                if event is None:
                    event, ptype = PacketCapture._parse(
                        packet, IP, TCP, UDP, ICMP, DNS, "", IPv6, stamp)
            except Exception as exc:
                # The point of replaying real traffic is to find these, so they
                # are counted by exception type instead of being swallowed.
                stats["malformed"] += 1
                stats[f"malformed_{type(exc).__name__}"] += 1
                continue
            if event is None:
                stats["not_ip"] += 1
                continue
            stats[f"parsed_{ptype}"] += 1
            stats["parsed"] += 1
            yield when, event, ptype


def replay(path: Path, cfg: DetectionConfig, limit: int | None = None):
    """Run one capture file through a fresh detector."""
    stats: Counter = Counter()
    detector = ThreatDetector(cfg)
    findings: list[tuple[float, object]] = []
    first = last = None
    started = time.monotonic()

    for when, event, ptype in read(path, stats, limit):
        if first is None:
            first = when
        last = when
        for alert in detector.process(event, ptype, now=when - first):
            findings.append((when, alert))

    stats["wall_seconds"] = round(time.monotonic() - started, 2)
    span = (last - first) if (first is not None and last is not None) else 0.0
    return findings, stats, (first, last, span)


# --------------------------------------------------------------------------
# ground truth
# --------------------------------------------------------------------------
@dataclass
class Attack:
    """One labelled attack window.

    ``sources``/``targets`` empty means "any address": some published
    schedules name only a time range.
    """
    label: str
    start: float
    end: float
    sources: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)

    def covers(self, when: float, source: str) -> bool:
        if not (self.start <= when <= self.end):
            return False
        return not self.sources or source in self.sources


def load_schedule(path: Path) -> list[Attack]:
    body = json.loads(Path(path).read_text())
    out = []
    for i, row in enumerate(body.get("attacks", [])):
        for key in ("label", "start", "end"):
            if key not in row:
                raise SystemExit(f"attack {i}: missing required key {key!r}")
        start, end = _epoch(row["start"]), _epoch(row["end"])
        if end < start:
            raise SystemExit(f"attack {i} ({row['label']}): end precedes start")
        out.append(Attack(str(row["label"]), start, end,
                          set(row.get("sources", [])),
                          set(row.get("targets", []))))
    if not out:
        raise SystemExit(f"{path}: no attacks defined")
    return out


def _epoch(value) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:          # a naive stamp is read as UTC, and says so
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def score(findings, attacks: list[Attack]) -> dict:
    """Score findings against labelled windows.

    Two different denominators, deliberately reported apart rather than folded
    into one number:

    * **finding precision** -- of the findings raised, how many landed inside a
      labelled window attributed to that source.
    * **window recall** -- of the labelled windows, how many produced at least
      one finding. A window is either caught or missed; ten findings inside it
      is still one window caught.
    """
    hits = [0] * len(attacks)
    true_positive = 0
    false_positive: Counter = Counter()

    for when, alert in findings:
        for i, attack in enumerate(attacks):
            if attack.covers(when, alert.source):
                hits[i] += 1
                true_positive += 1
                break
        else:
            false_positive[alert.threat] += 1

    total_fp = sum(false_positive.values())
    raised = true_positive + total_fp
    caught = sum(1 for h in hits if h)

    by_label: dict[str, dict] = {}
    for attack, hit in zip(attacks, hits, strict=True):
        row = by_label.setdefault(attack.label, {"windows": 0, "caught": 0,
                                                 "findings": 0})
        row["windows"] += 1
        row["caught"] += 1 if hit else 0
        row["findings"] += hit
    for row in by_label.values():
        row["window_recall"] = round(row["caught"] / row["windows"], 4)

    precision = (true_positive / raised) if raised else None
    recall = (caught / len(attacks)) if attacks else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else None)
    return {
        "findings_in_a_labelled_window": true_positive,
        "findings_outside_every_window": total_fp,
        "finding_precision": None if precision is None else round(precision, 4),
        "windows_total": len(attacks),
        "windows_caught": caught,
        "window_recall": None if recall is None else round(recall, 4),
        "f1": None if f1 is None else round(f1, 4),
        "per_label": by_label,
        "false_positives_by_threat": dict(false_positive.most_common()),
    }


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def parse_report(stats: Counter, span) -> dict:
    first, last, seconds = span
    read_count = stats.get("read", 0)
    parsed = stats.get("parsed", 0)
    malformed = stats.get("malformed", 0)
    return {
        "packets_read": read_count,
        "packets_parsed": parsed,
        "not_ip_or_arp": stats.get("not_ip", 0),
        "malformed": malformed,
        "malformed_rate": round(malformed / read_count, 6) if read_count else 0,
        "no_timestamp": stats.get("no_timestamp", 0),
        "out_of_order": stats.get("out_of_order", 0),
        "truncated_by_limit": bool(stats.get("truncated_by_limit")),
        "by_protocol": {k[len("parsed_"):]: v for k, v in sorted(stats.items())
                        if k.startswith("parsed_")},
        "exceptions": {k[len("malformed_"):]: v for k, v in sorted(stats.items())
                       if k.startswith("malformed_")},
        "capture_first": iso(first) if first else None,
        "capture_last": iso(last) if last else None,
        "capture_seconds": round(seconds, 3),
        "replay_wall_seconds": stats.get("wall_seconds", 0),
        "packets_per_second": (round(read_count / stats["wall_seconds"])
                               if stats.get("wall_seconds") else None),
    }


def render(data: dict) -> str:
    p = data["parsing"]
    out = [f"NEMOS {data['nemos_version']} — capture replay", "",
           f"file            {data['file']}", ""]
    out.append("PARSING")
    out.append(f"  packets read        {p['packets_read']:,}")
    out.append(f"  parsed to an event  {p['packets_parsed']:,}")
    out.append(f"  not IP/IPv6/ARP     {p['not_ip_or_arp']:,}")
    out.append(f"  malformed           {p['malformed']:,} "
               f"({p['malformed_rate'] * 100:.4f}%)")
    if p["exceptions"]:
        for name, count in p["exceptions"].items():
            out.append(f"      {name:<24} {count:,}")
    if p["out_of_order"]:
        out.append(f"  out of order        {p['out_of_order']:,}  "
                   "(windows assume a forward clock; sort the file if this is large)")
    if p["by_protocol"]:
        out.append("  by protocol         " + ", ".join(
            f"{k} {v:,}" for k, v in p["by_protocol"].items()))
    out.append(f"  capture span        {p['capture_seconds']:,.1f}s "
               f"({p['capture_first']} → {p['capture_last']})")
    if p["packets_per_second"]:
        out.append(f"  replay speed        {p['packets_per_second']:,} pkt/s "
                   f"in {p['replay_wall_seconds']}s wall")
    if p["truncated_by_limit"]:
        out.append("  NOTE                stopped early at --limit; "
                   "figures cover a prefix of the file only")

    out += ["", "FINDINGS", f"  raised              {data['findings_total']:,}"]
    for threat, count in data["findings_by_threat"].items():
        out.append(f"      {threat:<32} {count:,}")

    s = data.get("scoring")
    if s:
        out += ["", "AGAINST GROUND TRUTH"]
        out.append(f"  labelled windows    {s['windows_total']}")
        out.append(f"  windows caught      {s['windows_caught']}")
        pct = lambda v: "n/a" if v is None else f"{v * 100:.1f}%"  # noqa: E731
        out.append(f"  window recall       {pct(s['window_recall'])}")
        out.append(f"  finding precision   {pct(s['finding_precision'])}  "
                   f"({s['findings_in_a_labelled_window']:,} in a window, "
                   f"{s['findings_outside_every_window']:,} outside)")
        out.append(f"  F1                  {pct(s['f1'])}")
        out.append("")
        out.append(f"  {'attack label':<30} {'windows':>8} {'caught':>7} {'recall':>8}")
        for label, row in sorted(s["per_label"].items()):
            out.append(f"  {label:<30} {row['windows']:>8} {row['caught']:>7} "
                       f"{row['window_recall'] * 100:>7.1f}%")
        if s["false_positives_by_threat"]:
            out += ["", "  findings outside every labelled window:"]
            for threat, count in s["false_positives_by_threat"].items():
                out.append(f"      {threat:<32} {count:,}")
        out += ["", "  Precision and recall have different denominators here: "
                    "precision is per",
                "  finding, recall is per labelled window. A window is caught "
                    "or missed; ten",
                "  findings inside it is still one window caught."]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Replay a capture file through the NEMOS detection path.")
    ap.add_argument("pcap", type=Path, help="a .pcap or .pcapng file")
    ap.add_argument("--labels", type=Path,
                    help="attack schedule JSON; see docs/PCAP_REPLAY.md")
    ap.add_argument("--limit", type=int,
                    help="stop after N packets (sampling a large file)")
    ap.add_argument("--json", type=Path, help="write the full result here")
    args = ap.parse_args(argv)

    if not args.pcap.exists():
        raise SystemExit(f"{args.pcap}: no such file")

    attacks = load_schedule(args.labels) if args.labels else None
    findings, stats, span = replay(args.pcap, DetectionConfig.from_env(),
                                   args.limit)

    by_threat: Counter = Counter(a.threat for _, a in findings)
    data = {
        "nemos_version": VERSION,
        "file": str(args.pcap),
        "parsing": parse_report(stats, span),
        "findings_total": len(findings),
        "findings_by_threat": dict(by_threat.most_common()),
        "findings": [{"at": iso(w), "threat": a.threat, "source": a.source,
                      "severity": a.severity, "risk_score": a.risk_score,
                      "confidence": a.confidence, "reason": a.reason}
                     for w, a in findings],
    }
    if attacks:
        data["scoring"] = score(findings, attacks)

    print(render(data))
    if args.json:
        args.json.write_text(json.dumps(data, indent=2, sort_keys=True))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
