#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v go >/dev/null 2>&1; then
  if [ -x "$HOME/.local/go/bin/go" ]; then
    export PATH="$HOME/.local/go/bin:$PATH"
  else
    echo "Go is not installed. Install Go 1.26+ or place it at ~/.local/go." >&2
    exit 1
  fi
fi

mkdir -p bin
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/fvault ./cmd/fvault
echo "[OK] bin/fvault"
