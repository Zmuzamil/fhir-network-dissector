#!/usr/bin/env bash
# Start one network-lab scenario with the capture on.   ./netlab/lab-up.sh icu [DURATION]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
py="$here/../.venv/bin/python"; [ -x "$py" ] || py=python3
exec "$py" "$here/labctl.py" up "${1:?scenario: general|ward|laboratory|icu}" --duration "${2:-300}"
