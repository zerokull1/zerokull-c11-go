#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
make clean && make all && make verify-sha256 && sudo make install
echo "[ZEROKULL] Installed & SHA-256 verified."
