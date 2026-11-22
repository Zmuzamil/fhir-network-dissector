#!/usr/bin/env bash
# Every scenario in turn, then evaluate.   ./netlab/generate-captures.sh [scenario ...]
# Duration with DURATION=60 (default 300 s per scenario).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
py="$here/../.venv/bin/python"; [ -x "$py" ] || py=python3
exec "$py" "$here/labctl.py" generate "$@" --duration "${DURATION:-300}"
