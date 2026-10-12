#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════
# run.sh — Apex-PQ Universal Launcher (Native or Docker)
# ══════════════════════════════════════════════════════════════════════════
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

MODE="${1:-native}"

if [ "$MODE" = "docker" ]; then
    echo "🐳 Launching Apex-PQ inside Docker Container..."
    if command -v docker compose >/dev/null 2>&1; then
        docker compose up --build
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose up --build
    else
        echo "❌ Docker Compose not found. Please install Docker or run './run.sh native'"
        exit 1
    fi
else
    echo "🚀 Starting Apex-PQ Gateway & 3-Node BFT Ledger natively..."
    cd "$DIR/pqc-identity"
    python3 app.py
fi
