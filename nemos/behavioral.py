from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from math import sqrt
from typing import Iterable


@dataclass(frozen=True, slots=True)
class BehaviorObservation:
    rate: float
    bytes_rate: float
    unique_destinations: int
    unique_ports: int


@dataclass(frozen=True, slots=True)
class BehaviorResult:
    ready: bool
    anomaly_score: int
    confidence: int
    deviations: dict[str, float]
    baseline: dict[str, float]


@dataclass(slots=True)
class _Profile:
    samples: int = 0
    last_sample: float = 0.0
    rate_mean: float = 0.0
    rate_var: float = 0.0
    bytes_mean: float = 0.0
    bytes_var: float = 0.0
    dest_mean: float = 0.0
    dest_var: float = 0.0
    port_mean: float = 0.0
    port_var: float = 0.0


class AdaptiveBehaviorProfiler:
    """Small, deterministic, online baseline for explainable host anomalies.

    Uses exponentially weighted mean/variance. It is intentionally not a
    black-box ML claim: every anomaly can be explained as a deviation from a
    source's observed baseline. Profiles are bounded by max_sources.
    """

    def __init__(self, *, alpha: float = 0.15, min_samples: int = 8,
                 sample_interval: float = 5.0, sigma_threshold: float = 3.0,
                 max_sources: int = 4096):
        self.alpha = max(0.01, min(1.0, float(alpha)))
        self.min_samples = max(2, int(min_samples))
        self.sample_interval = max(0.0, float(sample_interval))
        self.sigma_threshold = max(1.0, float(sigma_threshold))
        self.max_sources = max(1, int(max_sources))
        self._profiles: OrderedDict[str, _Profile] = OrderedDict()

    @property
    def size(self) -> int:
        return len(self._profiles)

    def observe(self, source: str, now: float, obs: BehaviorObservation) -> BehaviorResult | None:
        p = self._profiles.get(source)
        if p is None:
            if len(self._profiles) >= self.max_sources:
                self._profiles.popitem(last=False)
            p = _Profile(last_sample=now)
            self._profiles[source] = p
        else:
            self._profiles.move_to_end(source)

        # A rolling packet window can produce the same observation hundreds
        # of times. Sample at a fixed cadence to prevent the baseline from
        # adapting to every packet and hiding a burst.
        if p.samples and now - p.last_sample < self.sample_interval:
            return None
        p.last_sample = now

        values = (obs.rate, obs.bytes_rate, float(obs.unique_destinations), float(obs.unique_ports))
        if p.samples < self.min_samples:
            self._seed_or_update(p, values)
            p.samples += 1
            return BehaviorResult(False, 0, 0, {}, self._baseline(p))

        # Capture the baseline before updating it with the current observation.
        # Evidence must describe what the event was compared against, not a
        # baseline that has already adapted to the event itself.
        baseline_before = self._baseline(p)
        means = (p.rate_mean, p.bytes_mean, p.dest_mean, p.port_mean)
        vars_ = (p.rate_var, p.bytes_var, p.dest_var, p.port_var)
        deviations = {}
        weighted = []
        names = ("rate", "bytes_rate", "unique_destinations", "unique_ports")
        for name, value, mean, var in zip(names, values, means, vars_):
            sd = sqrt(max(var, 1e-6))
            z = abs(value - mean) / sd if sd > 0 else 0.0
            deviations[name] = round(z, 3)
            weighted.append(min(6.0, z))

        self._seed_or_update(p, values)
        p.samples += 1
        strongest = max(weighted) if weighted else 0.0
        anomaly_score = min(100, int(45 + strongest * 10))
        confidence = min(98, int(50 + strongest * 8 + min(20, p.samples)))
        ready = strongest >= self.sigma_threshold
        return BehaviorResult(ready, anomaly_score, confidence, deviations, baseline_before)

    def _seed_or_update(self, p: _Profile, values: Iterable[float]) -> None:
        attrs = (("rate_mean", "rate_var"), ("bytes_mean", "bytes_var"),
                 ("dest_mean", "dest_var"), ("port_mean", "port_var"))
        for value, (mean_name, var_name) in zip(values, attrs):
            mean = getattr(p, mean_name)
            if p.samples == 0:
                setattr(p, mean_name, value)
                setattr(p, var_name, 0.0)
                continue
            delta = value - mean
            new_mean = mean + self.alpha * delta
            # EW variance update is stable and bounded for streaming values.
            new_var = (1.0 - self.alpha) * (getattr(p, var_name) + self.alpha * delta * delta)
            setattr(p, mean_name, new_mean)
            setattr(p, var_name, new_var)

    @staticmethod
    def _baseline(p: _Profile) -> dict[str, float]:
        return {
            "rate": round(p.rate_mean, 4),
            "bytes_rate": round(p.bytes_mean, 2),
            "unique_destinations": round(p.dest_mean, 2),
            "unique_ports": round(p.port_mean, 2),
            "samples": p.samples,
        }
