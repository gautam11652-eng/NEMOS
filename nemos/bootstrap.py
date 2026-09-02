"""Self-bootstrapping lifecycle for the ML anomaly model.

NEMOS ships no pretrained model on purpose: a forest fitted on another network
describes another network's normal. Historically that meant an operator had to
run ``tools/train_model.py`` by hand before ML scoring did anything, and most
never did -- so the ML layer sat permanently unavailable while the sensor ran.

This module closes that gap without changing what a model *means*. It watches
the analysis engine's own output, keeps only the windows that every existing
detection layer already judged unremarkable, and once it has enough of them
over a long enough period it fits a model on a background thread, validates it
against the live feature contract, and promotes it atomically.

Three properties are worth stating plainly, because they are what separate this
from "retrain on whatever is on the wire".

**It never trains on traffic NEMOS flagged.** A window enters the corpus only
when the fused assessment for that source came back ``NO_FINDING``: no
deterministic rule fired, the statistical baseline is not deviating, and any
active model scored it in the NORMAL band. There is no second detection
implementation here -- the filter is a reading of the existing one. Sources are
additionally quarantined for a few windows after any rule finding, because a
detection raised near the end of a window is fused into the *next* one.

**It never trains blindly on volume.** Row count alone is satisfied by ten
thousand copies of one idle window, which teaches a forest nothing and lets
genuinely unusual traffic land inside its notion of normal. A minimum wall-clock
observation period is required alongside the sample count, so the corpus spans
real variation rather than one quiet minute. ``ml.train`` enforces a distinct-row
floor on top of that.

**A failed retrain never costs a working model.** Training runs against a
staging directory. The new model is validated by the live engine -- same schema,
same feature names, same aggregation window -- before anything is promoted, and
the active model keeps scoring throughout. If validation fails, the staging
files are discarded and the sensor carries on with what it had.

The vetted corpus lives in the sensor's existing SQLite database, so a restart
resumes from the samples already collected rather than starting the observation
period again.
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .database import connect
from .features import FEATURE_SCHEMA_VERSION, FeatureVector
from .fusion import Assessment, VERDICT_BENIGN
from .ml import MIN_TRAINING_SAMPLES, AnomalyEngine, InsufficientTrainingData, sklearn_available

log = logging.getLogger(__name__)

# ---- Lifecycle states -------------------------------------------------------
# Deliberately few. Each one is a distinct thing an operator would do something
# different about; anything finer would be state for its own sake.

#: Automatic training cannot proceed at all (switched off, or no scikit-learn).
STATE_NO_MODEL = "NO_MODEL"
#: No active model; accumulating vetted-normal windows.
STATE_WARMING_UP = "WARMING_UP"
#: Fitting the first model on the background worker.
STATE_TRAINING = "TRAINING"
#: Fitted; checking it against the live feature contract before promotion.
STATE_VALIDATING = "VALIDATING"
#: A real model is loaded and scoring.
STATE_ACTIVE = "ACTIVE"
#: A model is active and scoring while a replacement is fitted.
STATE_RETRAINING = "RETRAINING"
#: Training or validation failed and nothing is active.
STATE_FAILED = "FAILED"

#: Directory name for the staging model, under the configured model directory.
STAGING_DIRNAME = ".staging"

#: Windows a source stays out of the corpus after a deterministic finding.
#: A rule fires inline on the capture thread and is fused into the *following*
#: window, so the window the alert was actually raised during would otherwise
#: look clean to this filter.
DEFAULT_QUARANTINE_WINDOWS = 3.0

#: Bound on the quarantine map. The key is a source address, so it must not be
#: allowed to grow without limit; evicted early like every other such map here.
MAX_QUARANTINED = 4096

#: How many buffered samples to hold in memory before a flush is forced. Also
#: the executemany batch size.
FLUSH_THRESHOLD = 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_iso(value: Any) -> float | None:
    try:
        return datetime.fromisoformat(str(value)).timestamp()
    except (TypeError, ValueError):
        return None


def is_clean(vector: FeatureVector, assessment: Assessment | None) -> tuple[bool, str]:
    """Whether one window may enter the training corpus, and why not if it may not.

    This is a *reading* of the existing detection layers, not a second opinion
    about them. ``assess`` in nemos/fusion.py has already combined deterministic
    rule findings, the statistical baseline and any active model into one
    verdict; anything other than ``NO_FINDING`` means at least one layer had
    something to say about this window, which is exactly the traffic a model of
    normal must not be fitted on.
    """
    if assessment is None:
        return False, "no assessment"
    if assessment.verdict != VERDICT_BENIGN:
        return False, f"verdict {assessment.verdict}"
    if assessment.signals and any(s.contribution > 0 for s in assessment.signals):
        # Belt and braces: a contributing signal under a benign verdict would
        # mean the fusion thresholds moved without this filter noticing.
        return False, "a detection layer contributed to this window"
    if vector.schema_version != FEATURE_SCHEMA_VERSION:
        return False, "feature schema mismatch"

    values = vector.values
    if len(values) != len(vector.as_row()):  # pragma: no cover - structural
        return False, "malformed feature vector"
    if not all(math.isfinite(v) for v in values):
        return False, "non-finite feature value"
    if vector.get("packets") <= 0:
        # An all-zero window describes silence, not normal traffic. Feeding
        # them in shrinks the spread the forest learns and makes real traffic
        # look unusual.
        return False, "empty window"
    return True, ""


class ModelBootstrap:
    """Collects vetted-normal windows and trains a model from them.

    Owned by :class:`nemos.analysis.AnalysisEngine`. Every method here is
    called from the analysis thread except the training worker, which runs on
    its own thread precisely so that fitting a forest cannot delay a window.
    """

    def __init__(self, *, engine: AnomalyEngine, db_path: Path | str,
                 window_seconds: float, enabled: bool = True,
                 min_seconds: float = 600.0, min_samples: int = 1000,
                 retrain_seconds: float = 86_400.0, max_samples: int = 20_000,
                 quarantine_windows: float = DEFAULT_QUARANTINE_WINDOWS):
        self.engine = engine
        self.db_path = Path(db_path)
        self.window_seconds = round(float(window_seconds), 3)
        self.enabled = bool(enabled)
        self.min_seconds = max(0.0, float(min_seconds))
        # Never below what ml.train will accept, or the bootstrap would trigger
        # a run that is guaranteed to be refused, forever.
        self.min_samples = max(MIN_TRAINING_SAMPLES, int(min_samples))
        self.retrain_seconds = max(0.0, float(retrain_seconds))
        self.max_samples = max(self.min_samples * 2, int(max_samples))
        self.quarantine_seconds = max(0.0, float(quarantine_windows)) * self.window_seconds

        self._lock = threading.Lock()
        self._buffer: list[tuple[str, str, float, int, str]] = []
        self._quarantine: OrderedDict[str, float] = OrderedDict()
        self._worker: threading.Thread | None = None
        self._stop = threading.Event()

        self._state = STATE_WARMING_UP if self.enabled else STATE_NO_MODEL
        self._reason = "" if self.enabled else "automatic training is disabled (NEMOS_ML_AUTOTRAIN=false)"
        self._last_error = ""
        self._trainings = 0
        self._failures = 0
        self._rejected = 0
        self._accepted = 0
        # Cached so status() does not run COUNT(*) on every dashboard poll.
        self._counts: tuple[int, float | None] = (0, None)
        self._counts_at = 0.0

        if self.enabled and not sklearn_available():
            self._state = STATE_NO_MODEL
            self._reason = (
                "scikit-learn is not installed, so no model can be trained. "
                "Deterministic rules and the statistical baseline are unaffected."
            )

    # ------------------------------------------------------------- lifecycle

    def start(self) -> None:
        """Adopt the engine's current state and announce the plan."""
        if self.engine.ready:
            self._set_state(STATE_ACTIVE, "")
            return
        if self._state == STATE_NO_MODEL:
            log.info("ML automatic training unavailable: %s", self._reason)
            return
        samples, _ = self._refresh_counts(force=True)
        log.info(
            "ML model not found; entering bootstrap mode "
            "(need %d clean samples over %.0fs; %d already collected)",
            self.min_samples, self.min_seconds, samples,
        )

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        with self._lock:
            worker = self._worker
        if worker is not None:
            worker.join(max(0.0, float(timeout)))
        self.flush()

    # --------------------------------------------------------------- ingress

    def note_rule_finding(self, source: str, now: float) -> None:
        """Quarantine a source that a deterministic rule just fired on."""
        if not self.enabled or not self.quarantine_seconds:
            return
        with self._lock:
            self._quarantine[source] = now + self.quarantine_seconds
            self._quarantine.move_to_end(source)
            while len(self._quarantine) > MAX_QUARANTINED:
                self._quarantine.popitem(last=False)

    def observe(self, vector: FeatureVector, assessment: Assessment | None,
                now: float) -> bool:
        """Offer one analysed window to the corpus. Returns whether it was kept."""
        if not self.enabled or self._state == STATE_NO_MODEL:
            return False
        if round(float(vector.window_seconds), 3) != self.window_seconds:
            return False

        with self._lock:
            until = self._quarantine.get(vector.source)
            if until is not None:
                if now < until:
                    self._rejected += 1
                    return False
                del self._quarantine[vector.source]

        keep, _why = is_clean(vector, assessment)
        if not keep:
            with self._lock:
                self._rejected += 1
            return False

        row = (_utc_now(), vector.source, self.window_seconds,
               vector.schema_version, json.dumps([round(v, 6) for v in vector.values]))
        with self._lock:
            self._buffer.append(row)
            self._accepted += 1
            full = len(self._buffer) >= FLUSH_THRESHOLD
        if full:
            self.flush()
        return True

    def flush(self) -> int:
        """Write buffered samples to the sensor's own database. Never raises."""
        with self._lock:
            pending, self._buffer = self._buffer, []
        if not pending:
            return 0
        try:
            c = connect(self.db_path)
            try:
                c.executemany(
                    """INSERT INTO ml_training_samples
                       (created_at, source, window_seconds, schema_version, features)
                       VALUES (?,?,?,?,?)""",
                    pending,
                )
                # Keep the corpus bounded. Oldest first, so what survives is the
                # most recent picture of the network.
                c.execute(
                    """DELETE FROM ml_training_samples WHERE id IN (
                           SELECT id FROM ml_training_samples
                           WHERE window_seconds=? AND schema_version=?
                           ORDER BY id DESC LIMIT -1 OFFSET ?)""",
                    (self.window_seconds, FEATURE_SCHEMA_VERSION, self.max_samples),
                )
                c.commit()
            finally:
                c.close()
        except sqlite3.Error:
            # Losing a batch of training samples is not worth stopping analysis
            # for; the next window offers more.
            log.exception("could not persist ML training samples")
            return 0
        # The cached count is now stale by exactly this batch. Left alone, the
        # cache can outlive several cycles of new samples and the training
        # trigger reads a total that never grows -- which is a bootstrap that
        # silently never fires.
        self._counts_at = 0.0
        return len(pending)

    # -------------------------------------------------------------- training

    def maybe_train(self, now: float | None = None) -> bool:
        """Start a training run if the conditions are met. Cheap when they are not."""
        if not self.enabled or self._stop.is_set():
            return False
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return False
            state = self._state
        if state == STATE_NO_MODEL:
            return False

        active = self.engine.ready
        if active and not self._retrain_due(now):
            return False

        samples, first_at = self._refresh_counts()
        if samples < self.min_samples:
            return False
        if self.min_seconds and first_at is not None:
            elapsed = (now if now is not None else time.time()) - first_at
            if elapsed < self.min_seconds:
                return False
        elif self.min_seconds and first_at is None:
            return False

        if not active:
            log.info("ML bootstrap observation period satisfied: %d clean samples", samples)
        self._set_state(STATE_RETRAINING if active else STATE_TRAINING, "")
        with self._lock:
            self._worker = threading.Thread(
                target=self._train_worker, args=(active,), name="ml-bootstrap", daemon=True,
            )
            self._worker.start()
        return True

    def _retrain_due(self, now: float | None) -> bool:
        """Whether the active model is old enough to be replaced.

        Keyed off the model's own recorded training time rather than a counter,
        so the cadence survives a restart without a second piece of state.
        """
        if not self.retrain_seconds:
            return False
        trained_at = _parse_iso(self.engine.status().get("metadata", {}).get("trained_at"))
        if trained_at is None:
            return True
        return ((now if now is not None else time.time()) - trained_at) >= self.retrain_seconds

    def _train_worker(self, had_model: bool) -> None:
        """Fit, validate and promote. Runs on its own thread; never raises."""
        verb = "retraining" if had_model else "training"
        try:
            log.info("ML %s started", verb)
            vectors = self._load_corpus()
            if len(vectors) < self.min_samples:
                raise InsufficientTrainingData(
                    f"corpus shrank to {len(vectors)} samples before training started"
                )

            staging_dir = self.engine.model_dir / STAGING_DIRNAME
            # A separate engine so a failure here cannot touch the live one.
            # window_seconds is left unset: train() records the window carried
            # by the vectors, and the live engine checks it during validation.
            staging = AnomalyEngine(staging_dir, random_state=self.engine.random_state)
            report = staging.train(vectors)
            log.info("ML %s completed: %d samples, model version %s",
                     verb, report.samples, report.model_version)

            self._set_state(STATE_VALIDATING, "")
            reason, model, metadata = self.engine.check(
                staging.model_path, staging.metadata_path,
            )
            if reason:
                raise ValueError(reason)
            log.info("ML model validation passed")

            self._promote(staging)
            # Install from the validated objects rather than re-reading disk:
            # the swap into the scoring path is then a single locked operation.
            self.engine.install(model, metadata)
            self._trainings += 1
            self._set_state(STATE_ACTIVE, "")
            log.info("ML model activated: version=%s samples=%d window=%.1fs",
                     metadata.get("model_version"), report.samples, self.window_seconds)
        except Exception as exc:
            self._failures += 1
            self._last_error = str(exc)
            if had_model and self.engine.ready:
                # The whole point of staging: the sensor keeps scoring.
                self._set_state(STATE_ACTIVE, "")
                log.warning("ML retraining failed; keeping existing model: %s", exc)
            else:
                self._set_state(STATE_FAILED, str(exc))
                log.warning("ML training failed: %s", exc)
        finally:
            self._discard_staging()
            with self._lock:
                self._worker = None

    def _promote(self, staging: AnomalyEngine) -> None:
        """Move the validated model into place with atomic replacements.

        Each file lands atomically. Between the two there is a moment where a
        *separate process* reading the directory would see the new model beside
        the old metadata; this process does not re-read them, it installs the
        objects it already validated. A concurrent reader is a training CLI run
        during a retrain, which is not a supported thing to do.
        """
        self.engine.model_dir.mkdir(parents=True, exist_ok=True)
        staging.model_path.replace(self.engine.model_path)
        staging.metadata_path.replace(self.engine.metadata_path)
        for path in (self.engine.model_path, self.engine.metadata_path):
            try:
                path.chmod(0o600)
            except OSError:
                pass

    def _discard_staging(self) -> None:
        staging_dir = self.engine.model_dir / STAGING_DIRNAME
        for name in (staging_dir.iterdir() if staging_dir.is_dir() else ()):
            try:
                name.unlink()
            except OSError:
                pass
        try:
            staging_dir.rmdir()
        except OSError:
            pass

    # ------------------------------------------------------------------ data

    def _load_corpus(self) -> list[FeatureVector]:
        """Read back the vetted samples for the *current* feature contract.

        Samples recorded under a different window or schema are left in place
        but never mixed in: counts and rates scale with the window, so a mixed
        corpus does not describe one distribution.
        """
        c = connect(self.db_path)
        try:
            rows = c.execute(
                """SELECT source, window_seconds, schema_version, features
                   FROM ml_training_samples
                   WHERE window_seconds=? AND schema_version=?
                   ORDER BY id DESC LIMIT ?""",
                (self.window_seconds, FEATURE_SCHEMA_VERSION, self.max_samples),
            ).fetchall()
        finally:
            c.close()

        vectors: list[FeatureVector] = []
        for row in rows:
            try:
                values = tuple(float(v) for v in json.loads(row["features"]))
            except (TypeError, ValueError):
                continue
            if not values or not all(math.isfinite(v) for v in values):
                continue
            vectors.append(FeatureVector(
                source=row["source"],
                window_seconds=float(row["window_seconds"]),
                values=values,
                schema_version=int(row["schema_version"]),
            ))
        return vectors

    def _refresh_counts(self, force: bool = False) -> tuple[int, float | None]:
        """Sample count and the epoch of the first one, cached briefly."""
        now = time.monotonic()
        if not force and now - self._counts_at < 2.0:
            return self._counts
        try:
            c = connect(self.db_path)
            try:
                row = c.execute(
                    """SELECT COUNT(*) AS n, MIN(created_at) AS first_at
                       FROM ml_training_samples
                       WHERE window_seconds=? AND schema_version=?""",
                    (self.window_seconds, FEATURE_SCHEMA_VERSION),
                ).fetchone()
            finally:
                c.close()
        except sqlite3.Error:
            return self._counts
        self._counts = (int(row["n"] or 0), _parse_iso(row["first_at"]))
        self._counts_at = now
        return self._counts

    # ----------------------------------------------------------------- state

    def _set_state(self, state: str, reason: str) -> None:
        with self._lock:
            self._state = state
            self._reason = reason

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def status(self) -> dict[str, Any]:
        """What the console shows. Every field is measured, none are estimated."""
        with self._lock:
            state, reason = self._state, self._reason
            buffered = len(self._buffer)
            stats = {
                "trainings": self._trainings,
                "failures": self._failures,
                "samples_accepted": self._accepted,
                "samples_rejected": self._rejected,
                "last_error": self._last_error,
            }
        samples, first_at = self._refresh_counts()
        samples += buffered
        elapsed = (time.time() - first_at) if first_at is not None else 0.0
        # An ACTIVE model has already met the bootstrap conditions; showing it
        # a progress bar afterwards would imply it is still warming up.
        warming = state in (STATE_WARMING_UP, STATE_TRAINING, STATE_VALIDATING, STATE_FAILED)
        return {
            "state": state,
            "enabled": self.enabled,
            "reason": reason,
            "auto_trained": self._trainings > 0,
            "samples": samples,
            "samples_required": self.min_samples,
            "observed_seconds": round(max(0.0, elapsed), 1),
            "observed_seconds_required": self.min_seconds,
            "progress": (
                round(min(1.0, samples / self.min_samples), 3) if warming and self.min_samples else None
            ),
            "window_seconds": self.window_seconds,
            "retrain_seconds": self.retrain_seconds,
            "max_samples": self.max_samples,
            "algorithm": "Isolation Forest",
            **stats,
        }


__all__ = [
    "DEFAULT_QUARANTINE_WINDOWS",
    "STATE_ACTIVE",
    "STATE_FAILED",
    "STATE_NO_MODEL",
    "STATE_RETRAINING",
    "STATE_TRAINING",
    "STATE_VALIDATING",
    "STATE_WARMING_UP",
    "ModelBootstrap",
    "is_clean",
]
