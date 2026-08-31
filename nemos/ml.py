"""Unsupervised anomaly detection over per-source traffic features.

The model is an Isolation Forest fitted on feature vectors extracted from
traffic the operator considers normal. It is unsupervised: it is never told what
an attack looks like, only what ordinary traffic for this network looks like,
and it reports how unusual a window is relative to that.

Three design decisions are worth stating plainly, because they are what make the
output defensible rather than impressive.

**The score measures depth into the training distribution's tail, and is not a
probability.** scikit-learn's ``decision_function`` returns an unbounded,
scale-free number that is meaningless on its own. At training time NEMOS records
that value's distribution across the training set; at inference a window is
placed against three reference points from it -- the median, the 5th percentile
and the minimum. Roughly 95% of training-like traffic therefore scores under 40,
and only a window more extreme than anything the model was fitted on reaches the
top band. See :meth:`AnomalyEngine._tail_score` for the exact mapping.

A plain percentile rank is the obvious alternative and is wrong: it spreads
training data uniformly over 0-100, so half of ordinary traffic would score
above 50.

**The feature schema is versioned.** A model records the schema it was fitted
against and refuses to score a vector built by a different one. Silently scoring
a reordered vector would produce confident nonsense.

**Absence is not failure.** scikit-learn is optional. If it is not installed, or
no model has been trained, or the model file is corrupt, the engine reports
itself unavailable and NEMOS continues with deterministic detection and the
statistical baseline. A missing model must never take down a sensor.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Sequence

from .features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FeatureVector

log = logging.getLogger(__name__)

MODEL_FORMAT_VERSION = 1
MODEL_FILENAME = "anomaly_model.joblib"
METADATA_FILENAME = "anomaly_model.json"

# Below this, an Isolation Forest has not seen enough variety for its notion of
# "normal" to mean anything. Training is refused rather than producing a model
# that scores confidently from almost no evidence.
MIN_TRAINING_SAMPLES = 50

# Row count alone is not enough. Ten thousand copies of the same window satisfy
# MIN_TRAINING_SAMPLES while telling the forest nothing: it fits a degenerate
# cloud, and genuinely unusual traffic can then land *inside* that cloud and
# score as normal. Distinct rows are what carry information, so they are
# checked separately.
MIN_DISTINCT_SAMPLES = 20

# Interpretation bands for the 0-100 anomaly score. Aligned with the mapping in
# AnomalyEngine._tail_score: roughly 95% of training-like traffic lands under
# BAND_NORMAL, and BAND_SUSPICIOUS is reached only below the training minimum.
# These are triage starting points, not thresholds with statistical meaning.
BAND_NORMAL = 40
BAND_SUSPICIOUS = 70
BAND_ANOMALOUS = 90


def sklearn_available() -> bool:
    """Whether scikit-learn can be imported in this environment."""
    try:
        import sklearn  # noqa: F401
        return True
    except Exception:
        return False


def classify(score: int) -> str:
    """Map a 0-100 anomaly score to a coarse band."""
    if score >= BAND_ANOMALOUS:
        return "HIGHLY_ANOMALOUS"
    if score >= BAND_SUSPICIOUS:
        return "ANOMALOUS"
    if score >= BAND_NORMAL:
        return "SUSPICIOUS"
    return "NORMAL"


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    """One scored window, with everything needed to explain the number."""

    source: str
    anomaly_score: int
    band: str
    raw_score: float
    model_version: str
    contributing_features: tuple[tuple[str, float], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "anomaly_score": self.anomaly_score,
            "band": self.band,
            "raw_score": round(self.raw_score, 6),
            "model_version": self.model_version,
            "contributing_features": [
                {"feature": name, "z_from_training_mean": round(value, 3)}
                for name, value in self.contributing_features
            ],
            "score_meaning": (
                "How far into the sparse tail of the training distribution this "
                "window falls, on a 0-100 scale. Under 40 is within the bulk of "
                "traffic the model was fitted on; 70 or above is more extreme "
                "than the training minimum. It is not a probability of compromise."
            ),
        }


@dataclass(frozen=True, slots=True)
class TrainingReport:
    samples: int
    features: int
    schema_version: int
    model_version: str
    contamination: str | float
    trained_at: str
    sklearn_version: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "features": self.features,
            "schema_version": self.schema_version,
            "model_version": self.model_version,
            "contamination": self.contamination,
            "trained_at": self.trained_at,
            "sklearn_version": self.sklearn_version,
        }


class InsufficientTrainingData(RuntimeError):
    """Raised when there are too few samples for training to be meaningful."""


class AnomalyEngine:
    """Loads, trains and applies the Isolation Forest.

    Inference and training are separate operations: the runtime only ever loads
    and scores. Training happens out of band via ``tools/train_model.py``.
    """

    def __init__(self, model_dir: Path | str, *, random_state: int = 42,
                 window_seconds: float | None = None):
        self.model_dir = Path(model_dir)
        self.random_state = random_state
        # The aggregation window is part of the feature contract: packet counts,
        # rates and flow counts all scale with it, so a model fitted on 10s
        # windows describes a different distribution from one fitted on 2s.
        # Recorded at training time and checked at load.
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._model: Any = None
        self._quantiles: list[float] = []
        self._feature_mean: list[float] = []
        self._feature_std: list[float] = []
        self._metadata: dict[str, Any] = {}
        self._unavailable_reason: str = "model not loaded"
        self.scored = 0

    # ---------------------------------------------------------------- state

    @property
    def model_path(self) -> Path:
        return self.model_dir / MODEL_FILENAME

    @property
    def metadata_path(self) -> Path:
        return self.model_dir / METADATA_FILENAME

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._model is not None

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "available": self._model is not None,
                "reason": None if self._model is not None else self._unavailable_reason,
                "sklearn_installed": sklearn_available(),
                "model_path": str(self.model_path),
                "scored_windows": self.scored,
                "schema_version": FEATURE_SCHEMA_VERSION,
                "metadata": dict(self._metadata),
                "bands": {
                    "NORMAL": f"0-{BAND_NORMAL - 1}",
                    "SUSPICIOUS": f"{BAND_NORMAL}-{BAND_SUSPICIOUS - 1}",
                    "ANOMALOUS": f"{BAND_SUSPICIOUS}-{BAND_ANOMALOUS - 1}",
                    "HIGHLY_ANOMALOUS": f"{BAND_ANOMALOUS}-100",
                },
            }

    # ------------------------------------------------------------- training

    def train(self, vectors: Sequence[FeatureVector], *,
              contamination: str | float = "auto",
              n_estimators: int = 200) -> TrainingReport:
        """Fit a model on feature vectors and persist it.

        Raises ``InsufficientTrainingData`` below the minimum sample count, and
        ``RuntimeError`` if scikit-learn is unavailable. Neither is caught here:
        training is an explicit operator action and should fail loudly.
        """
        if not sklearn_available():
            raise RuntimeError(
                "scikit-learn is required to train a model. "
                "Install it with: pip install -r requirements.txt"
            )
        if len(vectors) < MIN_TRAINING_SAMPLES:
            raise InsufficientTrainingData(
                f"need at least {MIN_TRAINING_SAMPLES} feature windows to train, "
                f"got {len(vectors)}. Capture more traffic, or lower the analysis "
                f"window so the same traffic yields more windows."
            )
        mismatched = [v.schema_version for v in vectors if v.schema_version != FEATURE_SCHEMA_VERSION]
        if mismatched:
            raise ValueError(
                f"training vectors use feature schema {mismatched[0]}, "
                f"this build expects {FEATURE_SCHEMA_VERSION}"
            )

        import sklearn
        import numpy as np
        from sklearn.ensemble import IsolationForest

        matrix = np.asarray([v.as_row() for v in vectors], dtype=float)

        distinct = len({tuple(row) for row in matrix.tolist()})
        if distinct < MIN_DISTINCT_SAMPLES:
            raise InsufficientTrainingData(
                f"training data contains only {distinct} distinct feature window(s) "
                f"across {len(vectors)} rows; at least {MIN_DISTINCT_SAMPLES} are "
                f"needed. Repeated identical windows carry no information, and a "
                f"model fitted on them scores unusual traffic as normal. Capture a "
                f"longer or more varied period."
            )

        # A feature that never varies in training cannot contribute to isolating
        # anything. Surfacing them is how an operator notices that, say, every
        # training window happened to be TCP-only.
        constant = [
            name for name, sd in zip(FEATURE_NAMES, matrix.std(axis=0), strict=True)
            if sd < 1e-12
        ]
        if constant:
            log.warning(
                "%d of %d features are constant across the training data and carry "
                "no signal: %s",
                len(constant), len(FEATURE_NAMES), ", ".join(constant),
            )

        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            # Fixed seed: two training runs over the same data must produce the
            # same model, or a reported result cannot be reproduced.
            random_state=self.random_state,
            n_jobs=1,
        )
        model.fit(matrix)

        # Calibration: record the training score distribution as a 101-point
        # quantile grid so inference can convert a raw score into a percentile.
        raw = model.decision_function(matrix)
        quantiles = [float(np.quantile(raw, q / 100.0)) for q in range(101)]

        # Per-feature mean/std lets inference explain *which* features were
        # unusual. The forest itself does not expose per-feature attribution.
        feature_mean = matrix.mean(axis=0).tolist()
        feature_std = matrix.std(axis=0).tolist()

        # Every training vector carries the window it was built from; they must
        # agree, or the corpus mixes incompatible feature scales.
        windows = {round(float(v.window_seconds), 3) for v in vectors}
        if len(windows) > 1:
            raise ValueError(
                f"training vectors mix aggregation windows {sorted(windows)}; "
                f"packet counts and rates scale with the window, so a mixed "
                f"corpus does not describe one distribution"
            )
        window_seconds = windows.pop()

        trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        model_version = f"{FEATURE_SCHEMA_VERSION}.{MODEL_FORMAT_VERSION}.{int(datetime.now(timezone.utc).timestamp())}"
        metadata = {
            "model_format_version": MODEL_FORMAT_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": list(FEATURE_NAMES),
            "model_version": model_version,
            "samples": len(vectors),
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": self.random_state,
            "trained_at": trained_at,
            "sklearn_version": sklearn.__version__,
            "window_seconds": window_seconds,
            "quantiles": quantiles,
            "feature_mean": feature_mean,
            "feature_std": feature_std,
        }

        self._persist(model, metadata)
        with self._lock:
            self._model = model
            self._quantiles = quantiles
            self._feature_mean = feature_mean
            self._feature_std = feature_std
            self._metadata = {k: v for k, v in metadata.items()
                              if k not in ("quantiles", "feature_mean", "feature_std")}
            self._unavailable_reason = ""

        return TrainingReport(
            samples=len(vectors),
            features=len(FEATURE_NAMES),
            schema_version=FEATURE_SCHEMA_VERSION,
            model_version=model_version,
            contamination=contamination,
            trained_at=trained_at,
            sklearn_version=sklearn.__version__,
        )

    def _persist(self, model: Any, metadata: dict[str, Any]) -> None:
        import joblib

        self.model_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.model_dir.chmod(0o700)
        except OSError:
            pass
        # Write to a temporary file and replace, so an interrupted write cannot
        # leave a half-written model that later loads as corrupt. The suffix is
        # appended rather than replaced: with_suffix would map both
        # "…joblib" and "…json" onto the same "….tmp" path.
        tmp_model = self.model_path.with_name(self.model_path.name + ".tmp")
        tmp_meta = self.metadata_path.with_name(self.metadata_path.name + ".tmp")
        joblib.dump(model, tmp_model)
        tmp_meta.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        tmp_model.replace(self.model_path)
        tmp_meta.replace(self.metadata_path)
        for path in (self.model_path, self.metadata_path):
            try:
                path.chmod(0o600)
            except OSError:
                pass

    # -------------------------------------------------------------- loading

    def load(self) -> bool:
        """Load a persisted model. Returns False and stays usable on failure.

        Every failure mode -- scikit-learn missing, no model on disk, corrupt
        file, schema mismatch -- results in an unavailable engine rather than an
        exception, because none of them should stop a sensor from capturing.
        """
        if not sklearn_available():
            self._set_unavailable("scikit-learn is not installed")
            return False
        if not self.model_path.is_file():
            self._set_unavailable(
                "no trained model found; run: python tools/train_model.py --help"
            )
            return False
        try:
            import joblib

            metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._set_unavailable("model metadata is missing; retrain the model")
            return False
        except (ValueError, OSError) as exc:
            self._set_unavailable(f"model metadata is unreadable: {exc}")
            return False

        schema = metadata.get("feature_schema_version")
        if schema != FEATURE_SCHEMA_VERSION:
            # Refusing here is the point: scoring a vector whose columns mean
            # something different from what the model was fitted on would
            # produce confident, wrong answers.
            self._set_unavailable(
                f"model was trained on feature schema {schema}, this build uses "
                f"{FEATURE_SCHEMA_VERSION}; retrain the model"
            )
            return False
        if metadata.get("feature_names") != list(FEATURE_NAMES):
            self._set_unavailable("model feature names do not match this build; retrain the model")
            return False

        try:
            model = joblib.load(self.model_path)
        except Exception as exc:
            self._set_unavailable(f"model file could not be loaded: {exc}")
            return False
        if not hasattr(model, "decision_function"):
            self._set_unavailable("model file does not contain a usable estimator")
            return False

        quantiles = metadata.get("quantiles") or []
        if len(quantiles) != 101:
            self._set_unavailable("model calibration data is missing or malformed; retrain")
            return False

        trained_window = metadata.get("window_seconds")
        if self.window_seconds is not None and trained_window is not None:
            if abs(float(trained_window) - float(self.window_seconds)) > 1e-6:
                # Scoring across a window mismatch is worse than not scoring:
                # every count and rate feature is on a different scale, so the
                # model reports confident numbers about a distribution it was
                # never fitted on.
                self._set_unavailable(
                    f"model was trained on {trained_window}s windows but this sensor "
                    f"aggregates {self.window_seconds}s windows. Counts and rates scale "
                    f"with the window, so the scores would be meaningless. Either set "
                    f"NEMOS_ANALYSIS_WINDOW={trained_window} or retrain with "
                    f"--window {self.window_seconds}."
                )
                return False

        with self._lock:
            self._model = model
            self._quantiles = [float(q) for q in quantiles]
            self._feature_mean = [float(v) for v in metadata.get("feature_mean", [])]
            self._feature_std = [float(v) for v in metadata.get("feature_std", [])]
            self._metadata = {k: v for k, v in metadata.items()
                              if k not in ("quantiles", "feature_mean", "feature_std")}
            self._unavailable_reason = ""
        log.info(
            "anomaly model loaded: version=%s samples=%s trained_at=%s",
            metadata.get("model_version"), metadata.get("samples"), metadata.get("trained_at"),
        )
        return True

    def _set_unavailable(self, reason: str) -> None:
        with self._lock:
            self._model = None
            self._quantiles = []
            self._metadata = {}
            self._unavailable_reason = reason
        log.info("anomaly model unavailable: %s", reason)

    # ------------------------------------------------------------ inference

    def score(self, vectors: Sequence[FeatureVector]) -> list[AnomalyResult]:
        """Score a batch of windows. Returns [] when the engine is unavailable.

        Batched deliberately: one ``decision_function`` call over N rows is far
        cheaper than N calls, and the analysis thread always has a batch.
        """
        if not vectors:
            return []
        with self._lock:
            model = self._model
            quantiles = list(self._quantiles)
            mean = list(self._feature_mean)
            std = list(self._feature_std)
            version = str(self._metadata.get("model_version", "unknown"))
        if model is None:
            return []

        usable = [v for v in vectors if v.schema_version == FEATURE_SCHEMA_VERSION]
        if len(usable) != len(vectors):
            log.warning("dropped %d feature vector(s) with a mismatched schema",
                        len(vectors) - len(usable))
        if not usable:
            return []

        try:
            import numpy as np

            matrix = np.asarray([v.as_row() for v in usable], dtype=float)
            raw_scores = model.decision_function(matrix)
        except Exception:
            # A scoring failure must not propagate into the analysis loop.
            log.exception("anomaly scoring failed; continuing without ML for this window")
            return []

        results = []
        for vector, raw in zip(usable, raw_scores, strict=True):
            raw = float(raw)
            score = self._tail_score(raw, quantiles)
            results.append(AnomalyResult(
                source=vector.source,
                anomaly_score=score,
                band=classify(score),
                raw_score=raw,
                model_version=version,
                contributing_features=self._contributions(vector, mean, std),
            ))
        with self._lock:
            self.scored += len(results)
        return results

    @staticmethod
    def _tail_score(raw: float, quantiles: list[float]) -> int:
        """Convert a raw decision-function value into a 0-100 anomaly score.

        ``quantiles`` is the ascending training distribution, so a *lower* raw
        value is more anomalous. The window's position is expressed in
        **robust deviation units**: how far below the training median it sits,
        measured in units of the median-to-5th-percentile spread.

            deviation = (q50 - raw) / (q50 - q05)

        Both anchors are robust. An earlier version used the training *minimum*
        as the "edge of normal" anchor, and that was wrong in a way worth
        recording: the minimum is by definition a single sample, so one unusual
        training window set the entire scale. Measured on this project's
        scenarios the minimum sat at -0.255 while the 5th percentile was
        -0.030, which stretched the band so far that a 259-port SYN scan scored
        65 -- indistinguishable from busy-but-benign traffic.

        The bands below come from measured separation on the synthetic
        scenarios, where held-out normal traffic reached 1.7 deviation units and
        every abnormal scenario fell between 2.6 and 3.3:

        ============================  ==========  ====================
        Deviation from training       Score       Band
        ============================  ==========  ====================
        at or above the median          0         NORMAL
        up to 1 unit below              0         NORMAL
        1 to 2 units below              0-40      NORMAL
        2 to 2.5 units below            40-70     SUSPICIOUS
        beyond 2.5 units                70-100    ANOMALOUS / HIGHLY
        ============================  ==========  ====================

        A plain percentile rank is the obvious alternative and is also wrong: it
        distributes training data uniformly over 0-100 by construction, so half
        of ordinary traffic would score above 50.

        The score says how far into the sparse tail of the training
        distribution a window sits. It is not a probability of compromise.
        """
        if not quantiles:
            return 0
        q05, q50 = quantiles[5], quantiles[50]
        scale = q50 - q05
        if scale <= 1e-12:
            # A degenerate training distribution carries no usable spread, so
            # there is no defensible way to grade a deviation against it.
            return 0
        deviation = (q50 - raw) / scale

        if deviation <= 1.0:
            return 0
        if deviation <= 2.0:
            return int(round(40 * (deviation - 1.0)))
        if deviation <= 2.5:
            return int(round(40 + 60 * (deviation - 2.0)))
        return int(min(100, round(70 + 60 * (deviation - 2.5))))

    @staticmethod
    def _contributions(vector: FeatureVector, mean: list[float], std: list[float],
                       limit: int = 5) -> tuple[tuple[str, float], ...]:
        """Which features are furthest from their training mean.

        This is an explanation aid, not the forest's internal attribution: an
        Isolation Forest does not expose per-feature contributions. It answers
        "what is unusual about this window" in the model's own feature space,
        which is what an analyst actually needs.
        """
        if len(mean) != len(FEATURE_NAMES) or len(std) != len(FEATURE_NAMES):
            return ()
        deviations = []
        for name, value, m, s in zip(FEATURE_NAMES, vector.values, mean, std, strict=True):
            # A zero-variance training feature cannot produce a meaningful
            # z-score; skip rather than dividing by an epsilon and reporting a
            # huge number for a one-unit change.
            if s <= 1e-9:
                continue
            deviations.append((name, (value - m) / s))
        deviations.sort(key=lambda item: abs(item[1]), reverse=True)
        return tuple(deviations[:limit])


__all__ = [
    "BAND_ANOMALOUS",
    "BAND_NORMAL",
    "BAND_SUSPICIOUS",
    "MIN_TRAINING_SAMPLES",
    "MODEL_FILENAME",
    "AnomalyEngine",
    "AnomalyResult",
    "InsufficientTrainingData",
    "TrainingReport",
    "classify",
    "sklearn_available",
]
