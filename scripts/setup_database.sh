#!/usr/bin/env bash
#
# Set up the CVE Intelligence Database on Linux.
# Creates data dirs, initialises the SQLite schema, and optionally does a first
# poll of NVD + OSV.
#
#   bash scripts/setup_database.sh            # init only
#   bash scripts/setup_database.sh --poll     # init + first NVD/OSV poll
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "ERROR: python3 not found. Install Python 3.10+ and re-run." >&2
    exit 1
fi

echo "[*] Initialising CVE intelligence database..."
"$PY" run.py db-setup

if [ "${1:-}" = "--poll" ]; then
    echo "[*] Performing first poll (NVD + OSV)..."
    "$PY" run.py db-poll --source all --hours 24 || \
        echo "[!] Poll failed (network?). You can retry later: python3 run.py db-poll --source all"
fi

echo "[+] Database setup complete: data/cve_intel.db"
