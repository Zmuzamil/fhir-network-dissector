#!/usr/bin/env bash
# FHIR network lab - one script for everything (Linux/macOS).
#
#   ./netlab/lab.sh generate [SCENARIO ...]     every (or the given) scenario, then evaluate
#   ./netlab/lab.sh run SCENARIO                one scenario: up + wait + down + evaluate
#   ./netlab/lab.sh up SCENARIO                 start one scenario and leave it running
#   ./netlab/lab.sh down                        stop it, merge the answer key
#   ./netlab/lab.sh evaluate                    re-evaluate captures/netlab/
# Run time per scenario: DURATION=60 ./netlab/lab.sh generate   (default 300 s)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
py="$here/../.venv/bin/python"; [ -x "$py" ] || py=python3
action="${1:?action: generate | run | up | down | evaluate}"; shift
case "$action" in
    generate)  exec "$py" "$here/labctl.py" generate "$@" --duration "${DURATION:-300}" ;;
    run|up)    exec "$py" "$here/labctl.py" "$action" "${1:?scenario: general|ward|laboratory|icu}" --duration "${DURATION:-300}" ;;
    down|evaluate) exec "$py" "$here/labctl.py" "$action" "$@" ;;
    *) echo "unknown action: $action" >&2; exit 2 ;;
esac
