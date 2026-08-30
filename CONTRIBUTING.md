# Contributing to NEMOS

Thanks for your interest. NEMOS is a defensive security tool, so contributions
are held to a slightly unusual standard: **claims must match behaviour.** A
feature that is documented but not implemented is worse than a missing feature,
because someone will rely on it.

## Scope

NEMOS is for monitoring networks you own or are authorized to monitor.
Contributions that add offensive capability, evasion, or targeting of third
parties will be declined.

## Getting set up

```bash
git clone https://github.com/gautam11652-eng/NEMOS.git
cd NEMOS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes the runtime dependencies plus pytest, ruff,
pip-audit and build.

## Before you open a pull request

Run what CI runs:

```bash
python -m pytest -q                            # tests
ruff check .                                   # lint
python -m compileall -q main.py nemos tests    # syntax
python -m pip_audit -r requirements.txt        # dependency audit
```

If you touched the dashboard:

```bash
node --check nemos/static/app.js
```

`make test`, `make compile` and `make audit` wrap the common ones.

## What a good change looks like

- **Tests come with behaviour.** A bug fix should include a test that fails
  without the fix. If you cannot write one, say why in the pull request.
- **Bounded state.** Any map keyed by something an attacker controls — a source
  address, a hostname — needs an eviction bound. Unbounded growth from spoofed
  input is a denial-of-service bug, and it will be treated as one.
- **Nothing expensive in the capture path.** `detector.py` and `behavioral.py`
  must not perform I/O. Persistence and delivery belong on their background
  threads.
- **Detection claims are evidence-backed.** If a detection cannot show the
  numbers that triggered it, it is not ready. Do not assign a MITRE ATT&CK
  technique unless the observed behaviour genuinely supports that mapping; an
  unmapped signal with a stated reason is the correct output when it does not.
- **Honest naming.** The behavioural baseline is a statistical model, not
  machine learning. Do not describe it as AI or ML in code, comments, the
  interface, or documentation.

## Detection-threshold changes

Detection tuning is a tradeoff, not an improvement. If you change a threshold,
the pull request should state:

- what traffic pattern motivated the change
- the expected effect on false positives and false negatives
- how you validated it (`python tools/validate_detection.py` is a safe start)

## Style

Follow the surrounding code. The codebase deliberately mixes a compact style in
small configuration modules with a more explicit style in the detection and
storage layers — match whichever file you are in.

Ruff configuration lives in `pyproject.toml`. Suppressions must be justified at
the site rather than added to the global ignore list, unless the rule is
genuinely wrong for the whole project.

## Security issues

Do not open a public issue for a vulnerability in NEMOS. See
[`SECURITY.md`](SECURITY.md).

## Never commit

Virtual environments, `__pycache__/`, databases, packet captures, `.env` files,
credentials, tokens, or generated artifacts. `.gitignore` covers the common
cases, but check `git status` before committing rather than trusting it.
