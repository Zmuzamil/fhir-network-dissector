#!/usr/bin/env bash
# Stop the network lab and merge the answer keys (works after an interrupted start).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
py="$here/../.venv/bin/python"; [ -x "$py" ] || py=python3
exec "$py" "$here/labctl.py" down
