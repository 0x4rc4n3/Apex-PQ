#!/usr/bin/env bash
# Apex-PQ launcher:  ./run.sh [native|docker|test]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
case "${1:-native}" in
  docker)
    docker compose up --build ;;
  test)
    cd pqc-identity && python3 -m unittest discover -s tests -v ;;
  native)
    export APEX_DEMO_MODE="${APEX_DEMO_MODE:-1}"
    echo "Starting Apex-PQ on http://127.0.0.1:8080 (demo mode: $APEX_DEMO_MODE, localhost only)"
    cd pqc-identity && exec python3 app.py ;;
  *) echo "usage: $0 [native|docker|test]"; exit 1 ;;
esac
