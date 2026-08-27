#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null || { echo "ERROR: python3 is required" >&2; exit 2; }
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3,10):
    raise SystemExit("ERROR: Python 3.10+ is required")
print(f"Python {sys.version.split()[0]}")
PY
if [[ ! -x .venv/bin/python ]]; then
  "$PYTHON_BIN" -m venv .venv
fi
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q main.py nemos tests
if command -v node >/dev/null 2>&1; then node --check nemos/static/app.js; fi
.venv/bin/python -m pytest -q
printf '\nNEMOS verification: PASS\n'
printf 'Start with: .venv/bin/python main.py\n'
