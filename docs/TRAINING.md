# Training the model

You do not have to. Start NEMOS, point it at authorized traffic, and it trains
its own model. The manual command below still works and is still the right tool
for training from a specific captured period.

## Automatic bootstrap (default)

A sensor with no model starts normally and reports `WARMING_UP`. Deterministic
rules and the statistical baseline run exactly as they always did — the model
is the third layer, not the load-bearing one.

While it warms up, NEMOS collects feature windows for its training corpus, and
this is the part that matters:

**It only keeps windows every detection layer judged unremarkable.** A window
enters the corpus when the fused assessment for that source came back
`NO_FINDING`: no deterministic rule fired, the statistical baseline is not
deviating, and any model already loaded scored it in the NORMAL band. There is
no second detection implementation involved — the filter reads the existing
one. A source is additionally held out for a few windows after any rule
finding, because a detection raised late in a window is fused into the next
one. So a sensor bootstrapping through a port scan does not learn that port
scanning is normal; it learns from the windows around it and excludes the scan.

**It will not train on volume alone.** A sample count is satisfied by one quiet
minute repeated, which teaches an Isolation Forest nothing and lets genuinely
unusual traffic land inside its notion of normal. Both
`NEMOS_ML_BOOTSTRAP_MIN_SAMPLES` and `NEMOS_ML_BOOTSTRAP_MIN_SECONDS` must be
satisfied, on top of the distinct-row floor training enforces anyway.

When both hold, NEMOS fits a model **on a background thread** — packet capture
and the analysis loop are never blocked — validates it against the live feature
contract (schema version, feature names, and the aggregation window), promotes
it with an atomic file replacement and activates it. The Sensor page shows the
state throughout.

The corpus lives in the sensor's own SQLite database, so restarting resumes
from the samples already collected rather than beginning the observation period
again.

Once a model is active, NEMOS refits it every `NEMOS_ML_RETRAIN_SECONDS` from
newly collected clean traffic. This is a *bounded* refit on a vetted corpus, not
continuous online learning: **the active model keeps scoring the whole time, and
a replacement is only promoted after it validates.** If a refit fails for any
reason, the working model is untouched and the sensor says so.

Set `NEMOS_ML_AUTOTRAIN=false` to keep training a manual operation.

## The honest limits of this

Automatic training narrows a real gap — before it, most deployments simply never
had a model — but it is not a free upgrade:

- A network that is already compromised when NEMOS is first deployed can have
  that compromise represented in its idea of normal, if the traffic is steady
  enough that no rule and no baseline ever flags it. Vetting excludes what NEMOS
  *detects*; it cannot exclude what NEMOS never noticed.
- Retraining follows a network as it changes, which is the point, and also means
  a slow enough change is followed rather than flagged. The daily default is a
  deliberate trade; `NEMOS_ML_RETRAIN_SECONDS=0` opts out.
- It is bootstrapping, not self-supervision. Nothing here evaluates whether the
  resulting model is *good* — no accuracy, precision or recall is computed or
  claimed, because nothing labelled exists to compute them against.

## From your own captured traffic (recommended)

Run NEMOS with capture enabled for a representative period — ideally a full
daily cycle — that you are reasonably confident is clean. Then:

```bash
python tools/train_model.py --source database --window 10
```

The model learns *your* network's normal, not a generic idea of normal.

Inspect the data before fitting anything to it:

```bash
python tools/train_model.py --source database --dry-run
```

## From synthetic traffic (evaluation and demo)

```bash
python tools/train_model.py --source synthetic --window 10
```

This generates RFC 5737 documentation traffic in memory. It proves the pipeline
works; it says nothing about your network, and the tool says so on completion.

## Knowing when to retrain

A model trained once and never revisited fails silently in both directions:
traffic drifts away from what it learned and ordinary work starts scoring
anomalous, or the network grows into what it considers normal and it stops
flagging what it should. Neither raises an error.

`/api/status` reports three independent signals under
`analysis.model.health`:

| Signal | Meaning |
| --- | --- |
| `age_days` / `stale` | Time since training. Reported separately from any verdict, because age alone is not evidence — a model on a stable network stays valid far longer than the 90-day mark that raises `stale`. |
| `drifted` / `drifted_features` | Each feature's live mean against its training mean, in training standard deviations. A feature 4+ sigmas out is named with its numbers; the model is only called drifted once ~a third of features have moved, since one moved feature is a changed service rather than a changed network. |
| `score_inflated` / `anomalous_fraction` | Share of windows in the anomalous bands. If most windows are anomalous, a stale calibration is the likelier explanation than a network under continuous attack. |

`drift_comparable` reports whether the comparison could run at all, so a
check that could not execute is never mistaken for one that passed.

None of these assert the model is wrong. They are the evidence for deciding
whether to retrain, and the report names which signal fired.

## Model lifecycle

- **Persistence** — model and calibration are written atomically to
  `data/model/`, with metadata recording the feature schema, feature names,
  aggregation window, sample count, scikit-learn version, seed and timestamp.
- **Loading** — automatic at startup. `GET /api/analysis` reports model state,
  version, training provenance and windows scored.
- **Reproducibility** — a fixed seed means two training runs over the same data
  produce identical scores.
- **Retraining** — rerun the command; the next start picks the new model up.
- **Refusal, not silence.** Training is refused for fewer than 50 windows, fewer
  than 20 *distinct* windows (repeated identical windows teach nothing and
  produce a model that scores real anomalies as normal), or a corpus mixing
  aggregation windows. Loading is refused on a schema, feature-name or window
  mismatch. Every refusal names the fix.
- **Absence is not failure.** No model, a corrupt model, or scikit-learn not
  installed leaves NEMOS running on deterministic rules plus the statistical
  baseline, with the reason reported in the API and on the dashboard.
