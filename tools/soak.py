#!/usr/bin/env python3
"""Run NEMOS under sustained load and record whether it stays bounded.

Every hot-path structure in NEMOS is bounded *by design* -- eviction appears
throughout detector.py, flows.py, behavioral.py and slowscan.py. Bounded by
design and bounded in practice are different claims, and only one of them has
evidence. This produces the evidence: drive a real sensor with continuous
traffic and sample the things that would grow if a bound were wrong.

    python tools/soak.py --minutes 120
    python tools/soak.py --minutes 10 --json soak.json

Traffic is generated against 127.0.0.1 only. Nothing leaves the machine.

What is sampled, and why each one matters:

* **RSS** -- the headline. A sensor that gains memory for a week is a sensor
  that dies at 3am on the night something happens.
* **threads** -- a thread leak is slower and quieter than a memory leak.
* **open file descriptors** -- the capture socket is now held for the life of
  the process, so a descriptor leak would be a new failure mode.
* **database bytes** -- retention is row-count based, so the file should
  plateau rather than climb forever.
* **queue depth and high-water** -- the writer's backpressure.
* **kernel drop rate** -- whether the sensor keeps up at this offered load.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rss_kb(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def threads_of(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Threads:"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def fds_of(pid: int) -> int | None:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def api(port: int, path: str, timeout: float = 5.0):
    url = f"http://127.0.0.1:{port}{path}"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def traffic(port: int, stop: threading.Event, rate: float = 1.0) -> None:
    """Continuous authorized loopback traffic, with periodic bursts.

    Steady noise alone would never exercise eviction. The sweeps keep creating
    *new* source/destination/port keys, which is what makes a bounded map prove
    it is bounded.
    """
    import random
    while not stop.is_set():
        for _ in range(max(1, int(random.randint(4, 12) * rate))):
            s = socket.socket(); s.settimeout(0.05)
            try:
                s.connect(("127.0.0.1", port))
                s.sendall(b"GET /api/health HTTP/1.0\r\n\r\n"); s.recv(64)
            except OSError:
                pass
            finally:
                s.close()
        if random.random() < 0.3 * rate:
            base = random.randint(1024, 60000)
            for p in range(base, base + random.randint(10, 40)):
                s = socket.socket(); s.settimeout(0.005)
                try:
                    s.connect(("127.0.0.1", p))
                except OSError:
                    pass
                finally:
                    s.close()
        if random.random() < 0.2 * rate:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for p in range(random.randint(2000, 9000), random.randint(9001, 9100)):
                try:
                    u.sendto(b"nemos-soak", ("127.0.0.1", p))
                except OSError:
                    break
            u.close()
        stop.wait(random.uniform(0.2, 0.8) / max(rate, 0.05))


def trend(series: list[float]) -> float | None:
    """Least-squares slope per sample. Near zero is the answer we want."""
    n = len(series)
    if n < 3:
        return None
    xs = list(range(n))
    mx, my = statistics.fmean(xs), statistics.fmean(series)
    denom = sum((x - mx) ** 2 for x in xs)
    if denom == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, series, strict=True)) / denom


def run(minutes: float, interval: float, port: int, workdir: Path,
        rate: float = 1.0, warmup: float = 300.0) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "NEMOS_PORT": str(port),
        "NEMOS_INTERFACE": "lo",
        "NEMOS_DB": str(workdir / "soak.db"),
        "NEMOS_MODEL_DIR": str(workdir / "model"),
        "NEMOS_LOG_LEVEL": "WARNING",
    }
    log = (workdir / "sensor.log").open("w")
    proc = subprocess.Popen([sys.executable, "main.py"], cwd=ROOT, env=env,
                            stdout=log, stderr=subprocess.STDOUT,
                            start_new_session=True)
    samples: list[dict] = []
    stop = threading.Event()
    started = time.monotonic()
    try:
        for _ in range(120):
            try:
                api(port, "/api/health", timeout=2); break
            except (urllib.error.URLError, OSError, TimeoutError):
                if proc.poll() is not None:
                    raise SystemExit(
                        f"sensor exited early; see {workdir}/sensor.log") from None
                time.sleep(1)
        else:
            raise SystemExit("sensor never became healthy")

        load = threading.Thread(target=traffic, args=(port, stop, rate),
                                daemon=True)
        load.start()
        deadline = started + minutes * 60
        db = workdir / "soak.db"

        while time.monotonic() < deadline:
            time.sleep(interval)
            if proc.poll() is not None:
                raise SystemExit(f"sensor died after {len(samples)} samples; "
                                 f"see {workdir}/sensor.log")
            try:
                status = api(port, "/api/status")
            except Exception as exc:                      # noqa: BLE001
                samples.append({"t": round(time.monotonic() - started, 1),
                                "api_error": f"{type(exc).__name__}: {exc}"})
                continue
            cap, wr = status.get("capture", {}), status.get("writer", {})
            samples.append({
                "t": round(time.monotonic() - started, 1),
                "rss_kb": rss_kb(proc.pid),
                "threads": threads_of(proc.pid),
                "fds": fds_of(proc.pid),
                "db_bytes": db.stat().st_size if db.exists() else 0,
                "packets": cap.get("packets_seen"),
                "drop_rate": cap.get("drop_rate"),
                "capture_state": cap.get("display_state"),
                "queue_depth": wr.get("queue_depth"),
                "queue_high_water": wr.get("queue_high_watermark"),
                "dropped_alerts": wr.get("dropped_alerts"),
                "write_errors": wr.get("write_errors"),
            })
    finally:
        stop.set()
        proc.terminate()
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

    ok = [s for s in samples if "rss_kb" in s and s["rss_kb"]]
    series = lambda k: [s[k] for s in ok if s.get(k) is not None]  # noqa: E731
    # Growth is measured after warm-up. A process fills caches, bootstraps the
    # ML buffer and opens its database in the first minutes; extrapolating that
    # slope to an hour reports a leak that is not there. The warm-up samples
    # are still recorded, just not fitted.
    settled = [s for s in ok if s["t"] >= warmup] or ok
    s_series = lambda k: [s[k] for s in settled if s.get(k) is not None]  # noqa: E731
    rss, thr, fds, dbb = series("rss_kb"), series("threads"), series("fds"), series("db_bytes")
    per_hour = 3600.0 / interval
    return {
        "minutes": minutes,
        "interval_seconds": interval,
        "samples": len(ok),
        "api_errors": sum(1 for s in samples if "api_error" in s),
        "warmup_seconds": warmup,
        "settled_samples": len(settled),
        "rss_kb": {"first": rss[0], "last": rss[-1], "max": max(rss),
                   "settled_first": s_series("rss_kb")[0],
                   "growth_kb_per_hour": round(
                       (trend(s_series("rss_kb")) or 0) * per_hour, 1)},
        "threads": {"first": thr[0], "last": thr[-1], "max": max(thr)},
        "fds": {"first": fds[0], "last": fds[-1], "max": max(fds)},
        "db_bytes": {"first": dbb[0], "last": dbb[-1],
                     "growth_bytes_per_hour": round(
                         (trend(s_series("db_bytes")) or 0) * per_hour)},
        "packets": ok[-1].get("packets"),
        "queue_high_water": max(series("queue_high_water") or [0]),
        "dropped_alerts": max(series("dropped_alerts") or [0]),
        "write_errors": max(series("write_errors") or [0]),
        "capture_states": sorted({s.get("capture_state") for s in ok if s.get("capture_state")}),
        "series": ok,
    }


def report(d: dict) -> str:
    r, t, f, db = d["rss_kb"], d["threads"], d["fds"], d["db_bytes"]
    lines = [
        f"NEMOS soak — {d['minutes']:g} minutes, {d['samples']} samples "
        f"every {d['interval_seconds']:g}s", "",
        f"  packets processed   {d['packets']:,}" if d.get("packets") else "",
        f"  capture states      {', '.join(d['capture_states'])}",
        "",
        f"  RSS                 {r['first']:,} -> {r['last']:,} kB  "
        f"(peak {r['max']:,})",
        f"      after warm-up   {r['settled_first']:,} kB at "
        f"{d['warmup_seconds']:g}s, trend {r['growth_kb_per_hour']:+,.1f} kB/hour",
        f"  threads             {t['first']} -> {t['last']}  (peak {t['max']})",
        f"  open fds            {f['first']} -> {f['last']}  (peak {f['max']})",
        f"  database            {db['first']:,} -> {db['last']:,} bytes",
        f"      growth          {db['growth_bytes_per_hour']:+,} bytes/hour",
        "",
        f"  queue high-water    {d['queue_high_water']:,}",
        f"  dropped alerts      {d['dropped_alerts']}",
        f"  write errors        {d['write_errors']}",
        f"  API errors          {d['api_errors']}",
    ]
    return "\n".join(x for x in lines if x != "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Soak-test a live NEMOS sensor.")
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--interval", type=float, default=30,
                    help="seconds between samples")
    ap.add_argument("--port", type=int, default=5090)
    ap.add_argument("--rate", type=float, default=1.0,
                    help="traffic intensity multiplier; lower it until the "
                         "sensor stays ONLINE, since a saturated sensor "
                         "measures overload rather than steady state")
    ap.add_argument("--warmup", type=float, default=300.0,
                    help="seconds excluded from the growth trend")
    ap.add_argument("--workdir", type=Path,
                    default=Path("/tmp/nemos-soak"))
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)

    data = run(args.minutes, args.interval, args.port, args.workdir,
               args.rate, args.warmup)
    print(report(data))
    if args.json:
        args.json.write_text(json.dumps(data, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
