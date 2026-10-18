#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PY="${PYTHON:-python3}"
if ! "$PY" -c 'import pymongo' 2>/dev/null; then
  "$PY" -m venv .venv && .venv/bin/pip install -q -r requirements.txt && PY=.venv/bin/python
fi
[ -x .venv/bin/python ] && PY=.venv/bin/python
"$PY" scenario.py
