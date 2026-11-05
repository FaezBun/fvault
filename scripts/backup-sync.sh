#!/usr/bin/env bash
set -euo pipefail

BIN="${FVAULT_BIN:-/opt/fvault/bin/fvault}"
export FVAULT_HOME="${FVAULT_HOME:-/var/lib/fvault}"

if [ ! -x "$BIN" ]; then
  echo "fvault binary not found at $BIN" >&2
  exit 1
fi

echo "[i] fvault backup sync $(date -u +%Y-%m-%dT%H:%M:%SZ)"
"$BIN" backup sync

echo "[i] fvault backup prune"
"$BIN" backup prune

echo "[OK] backup job finished"
