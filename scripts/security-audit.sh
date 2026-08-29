#!/usr/bin/env bash
set -euo pipefail
python -m compileall -q main.py nemos tests
python -m pytest -q
python -m pip_audit -r requirements.txt
