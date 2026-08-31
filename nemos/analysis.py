"""Windowed analysis: flows in, fused assessments out.

This is where the ML layer meets the running sensor, and the whole point of the
module is *where the work happens*. The capture thread does one cheap thing per
packet -- append to a flow table under a short lock. Everything expensive
(window expiry, feature extraction, batched inference, fusion) happens on a
separate thread on a fixed cadence.

That separation is not an optimisation, it is a correctness requirement. A
packet handler that blocks is a packet handler that drops traffic, and inference
latency must never be able to reach the capture path.

Per cycle the engine:

1. expires flows whose window has closed,
2. groups them by originating host,
3. extracts one feature vector per host,
4. scores the whole batch in a single model call,
5. updates each host's statistical baseline,
6. fuses rule findings, ML score and baseline state into an assessment,
7. emits an alert for anything actionable.

Deterministic rules still run inline on the capture thread, where they belong:
they are cheap and they should fire on the packet that triggers them, not up to
a window later.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable, Sequence

from .behavioral import STATE_NO_BASELINE, AdaptiveBehaviorProfiler, BehaviorObservation, BehaviorResult
from .features import FeatureVector, extract_all
from .flows import Flow, FlowTable, group_by_source
from .fusion import Assessment, assess
from .ml import AnomalyEngine
from .models import Alert, TrafficEvent, utc_now

log = logging.getLogger(__name__)

DEFAULT_WINDOW_SECONDS = 10.0

#: How many recent assessments and windows to keep for the API to serve.
RECENT_ASSESSMENTS = 200
RECENT_WINDOWS = 100

#: Bound on remembered rule findings awaiting fusion. The key is a source
#: address, so this must not grow without limit.
MAX_PENDING_SOURCES = 4096

#: Suppress repeat statistical findings per source, mirroring the detector's
#: own cooldown so a sustained anomaly does not alert every window.
DEFAULT_ANOMALY_COOLDOWN = 120.0


@dataclass(frozen=True, slots=True)
class WindowResult:
    """One completed analysis cycle."""

    started_at: str
    window_seconds: float
    flows: int
    sources: int
    assessments: tuple[Assessment, ...]
    scored_by_model: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "window_seconds": self.window_seconds,
            "flows": self.flows,
            "sources": self.sources,
            "scored_by_model": self.scored_by_model,
            "assessments": [a.as_dict() for a in self.assessments],
        }


class AnalysisEngine:
    """Owns the flow table, the baseline profiler and the anomaly model."""

    def __init__(self, *, model_dir, window_seconds: float = DEFAULT_WINDOW_SECONDS,
                 profiler: AdaptiveBehaviorProfiler | None = None,
                 on_alert: Callable[[Alert], None] | None = None,
                 on_flows: Callable[[Sequence[Flow]], None] | None = None,
                 max_flows: int = 20_000,
                 anomaly_cooldown: float = DEFAULT_ANOMALY_COOLDOWN):
        self.window_seconds = max(1.0, float(window_seconds))
        self.on_alert = on_alert
        self.on_flows = on_flows
        self.anomaly_cooldown = max(0.0, float(anomaly_cooldown))

        # The flow table is shared between the capture thread and the analysis
        # thread, so every access is under this lock. It is held only for the
        # duration of a dict operation, never across I/O.
        self._flow_lock = threading.Lock()
        self._flows = FlowTable(
            max_flows=max_flows,
            idle_timeout=self.window_seconds,
            max_duration=self.window_seconds * 6,
        )

        self.model = AnomalyEngine(model_dir, window_seconds=self.window_seconds)
        self.profiler = profiler or AdaptiveBehaviorProfiler(sample_interval=0.0)

        self._state_lock = threading.Lock()
        self._pending_rules: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
        self._baselines: OrderedDict[str, BehaviorResult] = OrderedDict()
        self._last_anomaly: OrderedDict[str, float] = OrderedDict()
        self._recent: list[Assessment] = []
        self._windows: list[WindowResult] = []

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.cycles = 0
        self.alerts_emitted = 0
        self.suppressed = 0

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self.model.load()  # never raises; unavailable is a valid state
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="analysis", daemon=True)
            self._thread.start()
        status = self.model.status()
        log.info(
            "analysis engine started: window=%.1fs ml=%s",
            self.window_seconds,
            "enabled" if status["available"] else f"disabled ({status['reason']})",
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._state_lock:
            thread = self._thread
        if thread is not None:
            thread.join(max(0.0, float(timeout)))
        with self._state_lock:
            self._thread = None

    def _run(self) -> None:
        # Wake more often than the window so expiry is timely, but only do work
        # when there is something to expire.
        tick = max(0.5, self.window_seconds / 4.0)
        while not self._stop.wait(tick):
            try:
                self.run_cycle()
            except Exception:  # the analysis thread must never die
                log.exception("analysis cycle failed; continuing")

    # -------------------------------------------------------------- ingress

    def observe(self, event: TrafficEvent) -> None:
        """Record one packet. Called from the capture thread; must stay cheap."""
        with self._flow_lock:
            self._flows.observe(event)

    def record_rule_alerts(self, source: str, alerts: Sequence[Alert]) -> None:
        """Remember deterministic findings so the next cycle can fuse them."""
        if not alerts:
            return
        with self._state_lock:
            bucket = self._pending_rules.setdefault(source, [])
            bucket.extend(a.as_dict() for a in alerts)
            # Keep only what a single window could plausibly need.
            if len(bucket) > 50:
                del bucket[:-50]
            self._pending_rules.move_to_end(source)
            while len(self._pending_rules) > MAX_PENDING_SOURCES:
                self._pending_rules.popitem(last=False)

    # ---------------------------------------------------------------- cycle

    def run_cycle(self, now: float | None = None, *, force: bool = False) -> WindowResult | None:
        """Run one analysis window. Returns None when there is nothing to do."""
        now = time.monotonic() if now is None else now
        with self._flow_lock:
            expired = self._flows.expire(now, force=force)
        if not expired:
            return None

        if self.on_flows is not None:
            try:
                self.on_flows(expired)
            except Exception:
                log.exception("flow persistence callback failed")

        grouped = group_by_source(expired)
        vectors = extract_all(grouped, self.window_seconds)
        anomalies = {r.source: r for r in self.model.score(vectors)}

        assessments: list[Assessment] = []
        for vector in vectors:
            baseline = self._update_baseline(vector, now)
            with self._state_lock:
                rules = self._pending_rules.pop(vector.source, [])
            result = assess(
                vector.source,
                rule_alerts=rules,
                anomaly=anomalies.get(vector.source),
                baseline=baseline,
            )
            assessments.append(result)
            if result.actionable:
                self._emit(result, vector, now)

        window = WindowResult(
            started_at=utc_now(),
            window_seconds=self.window_seconds,
            flows=len(expired),
            sources=len(grouped),
            assessments=tuple(assessments),
            scored_by_model=len(anomalies),
        )
        with self._state_lock:
            self.cycles += 1
            self._recent.extend(a for a in assessments if a.actionable)
            del self._recent[:-RECENT_ASSESSMENTS]
            self._windows.append(window)
            del self._windows[:-RECENT_WINDOWS]
        return window

    def _update_baseline(self, vector: FeatureVector, now: float) -> BehaviorResult | None:
        """Feed the window's features into this source's statistical baseline."""
        observation = BehaviorObservation(
            rate=vector.get("packets_per_second"),
            bytes_rate=vector.get("bytes_per_second"),
            unique_destinations=int(vector.get("unique_destinations")),
            unique_ports=int(vector.get("unique_destination_ports")),
        )
        result = self.profiler.observe(vector.source, now, observation)
        if result is not None:
            with self._state_lock:
                self._baselines[vector.source] = result
                self._baselines.move_to_end(vector.source)
                while len(self._baselines) > MAX_PENDING_SOURCES:
                    self._baselines.popitem(last=False)
        return result

    def _emit(self, result: Assessment, vector: FeatureVector, now: float) -> None:
        """Emit an alert for a purely statistical finding.

        Deterministic findings already produced their own alerts inline on the
        capture thread; re-emitting them here would duplicate. This path exists
        for windows where only ML or the baseline fired.
        """
        if result.techniques or any(s.layer == "rules" for s in result.signals):
            return
        if self.anomaly_cooldown:
            with self._state_lock:
                previous = self._last_anomaly.get(result.source)
                if previous is not None and now - previous < self.anomaly_cooldown:
                    self._last_anomaly.move_to_end(result.source)
                    self.suppressed += 1
                    return
                self._last_anomaly[result.source] = now
                self._last_anomaly.move_to_end(result.source)
                while len(self._last_anomaly) > MAX_PENDING_SOURCES:
                    self._last_anomaly.popitem(last=False)

        alert = Alert(
            timestamp=utc_now(),
            threat="ML_TRAFFIC_ANOMALY" if result.anomaly_score is not None else "BEHAVIORAL_TRAFFIC_ANOMALY",
            category="ANOMALOUS_BEHAVIOR",
            source=result.source,
            severity=result.severity,
            risk_score=result.risk_score,
            confidence=result.confidence,
            reason="; ".join(result.reasons[:3]) or "statistical deviation from baseline",
            packets=int(vector.get("packets")),
            destinations=int(vector.get("unique_destinations")),
            ports=int(vector.get("unique_destination_ports")),
            window_seconds=int(self.window_seconds),
            # Deliberately no technique: statistical evidence does not
            # establish a named adversary technique.
            technique="",
            evidence={
                "verdict": result.verdict,
                "detection_layers": list(result.layers),
                "anomaly_score": result.anomaly_score,
                "baseline_state": result.baseline_state,
                "reasons": list(result.reasons),
                "explanation": dict(result.explanation),
                "features": vector.describe()["features"],
                "signals": [s.as_dict() for s in result.signals],
            },
        )
        with self._state_lock:
            self.alerts_emitted += 1
        if self.on_alert is not None:
            try:
                self.on_alert(alert)
            except Exception:
                log.exception("alert callback failed")

    # ------------------------------------------------------------- read API

    def baseline_for(self, source: str) -> dict[str, Any]:
        with self._state_lock:
            result = self._baselines.get(source)
        if result is None:
            return {"source": source, "state": STATE_NO_BASELINE, "samples": 0,
                    "reason": "no observations recorded for this host yet"}
        return {
            "source": source,
            "state": result.state,
            "samples": result.samples,
            "strongest_sigma": result.strongest_sigma,
            "deviations_sigma": dict(result.deviations),
            "baseline": dict(result.baseline),
        }

    def baselines(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._state_lock:
            sources = list(self._baselines)[-limit:]
        return [self.baseline_for(source) for source in reversed(sources)]

    def recent_assessments(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._state_lock:
            recent = self._recent[-limit:]
        return [a.as_dict() for a in reversed(recent)]

    def recent_windows(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._state_lock:
            windows = self._windows[-limit:]
        return [w.as_dict() for w in reversed(windows)]

    def active_flows(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._flow_lock:
            snapshot = self._flows.snapshot()
        snapshot.sort(key=lambda f: f.last_seen, reverse=True)
        return [flow.as_dict() for flow in snapshot[:limit]]

    def status(self) -> dict[str, Any]:
        with self._flow_lock:
            flow_metrics = self._flows.metrics()
        with self._state_lock:
            state = {
                "cycles": self.cycles,
                "alerts_emitted": self.alerts_emitted,
                "suppressed": self.suppressed,
                "tracked_baselines": len(self._baselines),
                "pending_rule_sources": len(self._pending_rules),
                "running": bool(self._thread and self._thread.is_alive()),
            }
        return {
            "window_seconds": self.window_seconds,
            "flows": flow_metrics,
            "model": self.model.status(),
            **state,
        }


__all__ = [
    "DEFAULT_ANOMALY_COOLDOWN",
    "DEFAULT_WINDOW_SECONDS",
    "AnalysisEngine",
    "WindowResult",
]
