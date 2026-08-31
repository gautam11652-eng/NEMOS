"""Notice when the anomaly model has stopped describing the network.

An Isolation Forest learns one network at one point in time. NEMOS trains it
locally, by hand, and then never mentions it again -- so the failure mode is
silent in both directions and gets worse the longer it goes unnoticed:

- Traffic drifts away from the training distribution (new services, a VLAN
  migration, a doubled user count) and the model flags ordinary work as
  anomalous. The operator learns to ignore the layer.
- Or the network grows *into* behaviour the model was trained to consider
  normal, and it stops flagging things it should.

Neither produces an error. The dashboard shows a model that is loaded and
scoring, which is exactly what it shows when everything is fine.

This module reports three independent signals, all derived from data the
model already persists at training time:

**Age.** How long since it was trained. Not evidence of anything by itself,
which is why it is reported separately rather than folded into a verdict.

**Feature drift.** The live mean of each feature against the training mean,
in units of the training standard deviation. A feature sitting several
training-sigmas away means the model is scoring traffic unlike anything it
learned from.

**Score inflation.** The share of windows landing in the anomalous bands. The
model was calibrated so that share should be small; if most windows are
anomalous, the more likely explanation is a stale model rather than a network
under continuous attack.

None of these is asserted as "the model is wrong". They are the evidence an
operator needs to decide whether to retrain, and the module says which of the
three fired.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from datetime import datetime, timezone

# Below this many scored windows the live statistics are too thin to compare
# against anything, and any verdict would be noise.
MIN_SAMPLES_FOR_DRIFT = 200

# A feature this many training-sigmas from its training mean is no longer
# described by the model. Deliberately generous: the point is to catch a
# distribution that has moved, not to react to a busy afternoon.
DRIFT_SIGMA = 4.0

# Share of features that must have drifted before the model as a whole is
# called drifted. One moved feature is a changed service; a third of them is a
# different network.
DRIFT_FEATURE_FRACTION = 0.30

# Share of windows in the anomalous bands above which the calibration is more
# likely stale than the network is hostile.
SCORE_INFLATION_FRACTION = 0.50

# Anomaly score at or above which a window counts as anomalous, matching
# ml.BAND_SUSPICIOUS.
ANOMALOUS_SCORE = 40

DAY_SECONDS = 86_400.0

# Age at which retraining is worth surfacing. Not a correctness threshold --
# a model trained on a stable network stays valid far longer than this.
STALE_AFTER_DAYS = 90.0


class DriftMonitor:
    """Running comparison of live traffic against what the model was trained on.

    Updated once per scored window on the analysis thread, never on the
    capture path. Cost is O(features) per window with no allocation, using
    Welford's method so the running variance stays numerically stable over
    the millions of windows a long-lived sensor will produce.
    """

    __slots__ = ("_lock", "_count", "_mean", "_m2", "_anomalous", "_features")

    def __init__(self, features: int = 0) -> None:
        self._lock = threading.Lock()
        self._features = features
        self._count = 0
        self._mean: list[float] = [0.0] * features
        self._m2: list[float] = [0.0] * features
        self._anomalous = 0

    def observe(self, values: Sequence[float], score: int) -> None:
        """Fold one scored window into the running statistics."""
        with self._lock:
            if self._features == 0 and values:
                self._features = len(values)
                self._mean = [0.0] * self._features
                self._m2 = [0.0] * self._features
            if len(values) != self._features:
                # A vector of the wrong width belongs to a different feature
                # schema; mixing it in would compare unrelated quantities.
                return
            self._count += 1
            count = self._count
            for index, value in enumerate(values):
                delta = value - self._mean[index]
                self._mean[index] += delta / count
                self._m2[index] += delta * (value - self._mean[index])
            if score >= ANOMALOUS_SCORE:
                self._anomalous += 1

    def reset(self) -> None:
        """Forget the live statistics, after a retrain."""
        with self._lock:
            self._count = 0
            self._mean = [0.0] * self._features
            self._m2 = [0.0] * self._features
            self._anomalous = 0

    def assess(self, metadata: dict, now: datetime | None = None) -> dict:
        """Report model health against the metadata it was trained with."""
        now = now or datetime.now(timezone.utc)
        with self._lock:
            count = self._count
            live_mean = list(self._mean)
            anomalous = self._anomalous

        report: dict = {
            "scored_windows": count,
            "age_days": None,
            "trained_at": metadata.get("trained_at"),
            "training_samples": metadata.get("samples"),
            "stale": False,
            "drifted": False,
            "score_inflated": False,
            "drifted_features": [],
            "anomalous_fraction": (round(anomalous / count, 3) if count else None),
            "drift_comparable": None,
            "reasons": [],
        }

        age_days = _age_days(metadata.get("trained_at"), now)
        if age_days is not None:
            report["age_days"] = round(age_days, 1)
            if age_days >= STALE_AFTER_DAYS:
                report["stale"] = True
                report["reasons"].append(
                    f"the model was trained {int(age_days)} days ago; retrain it on "
                    "traffic that reflects the network as it is now"
                )

        if count < MIN_SAMPLES_FOR_DRIFT:
            # Say so rather than reporting a verdict from too little data.
            report["reasons"].append(
                f"only {count} windows scored so far; drift is not assessed below "
                f"{MIN_SAMPLES_FOR_DRIFT}"
            )
            return report

        training_mean = metadata.get("feature_mean") or []
        training_std = metadata.get("feature_std") or []
        names = metadata.get("feature_names") or []
        drifted: list[dict] = []
        comparable_widths = len(training_mean) == len(live_mean) == len(training_std)
        if not comparable_widths:
            # Say so. Returning drifted=False here without explanation is
            # indistinguishable from a healthy model, and that is exactly how
            # this check was once silently disabled: the caller passed
            # metadata that did not carry the training mean and spread, and
            # traffic dozens of sigmas away was reported as no drift at all.
            report["reasons"].append(
                "feature drift could not be assessed: the model metadata does not "
                "carry a training mean and spread of the same width as the live "
                "features"
            )
        report["drift_comparable"] = comparable_widths
        if comparable_widths:
            for index, (observed, expected, spread) in enumerate(
                zip(live_mean, training_mean, training_std, strict=True)
            ):
                # A zero-variance feature in training cannot be expressed in
                # sigmas; skip it rather than dividing by a floor and
                # manufacturing an enormous deviation.
                if not spread or spread <= 0:
                    continue
                sigma = abs(observed - expected) / spread
                if sigma >= DRIFT_SIGMA:
                    drifted.append({
                        "feature": names[index] if index < len(names) else f"feature_{index}",
                        "training_mean": round(float(expected), 4),
                        "observed_mean": round(float(observed), 4),
                        "sigma": round(float(sigma), 2),
                    })

        report["drifted_features"] = drifted
        comparable = sum(1 for spread in training_std if spread and spread > 0)
        if comparable and len(drifted) / comparable >= DRIFT_FEATURE_FRACTION:
            report["drifted"] = True
            report["reasons"].append(
                f"{len(drifted)} of {comparable} features have moved more than "
                f"{DRIFT_SIGMA:g} training sigmas from the training distribution; "
                "the model is scoring traffic it was not trained on"
            )

        fraction = anomalous / count
        if fraction >= SCORE_INFLATION_FRACTION:
            report["score_inflated"] = True
            report["reasons"].append(
                f"{fraction:.0%} of windows scored anomalous; a model calibrated on "
                "this network would flag far fewer, so the calibration is more "
                "likely stale than the network continuously hostile"
            )

        return report


def _age_days(trained_at: str | None, now: datetime) -> float | None:
    if not trained_at:
        return None
    try:
        then = datetime.fromisoformat(str(trained_at))
    except (TypeError, ValueError):
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0.0, (now - then).total_seconds() / DAY_SECONDS)


__all__ = [
    "DriftMonitor",
    "ANOMALOUS_SCORE",
    "DRIFT_SIGMA",
    "MIN_SAMPLES_FOR_DRIFT",
    "STALE_AFTER_DAYS",
]
