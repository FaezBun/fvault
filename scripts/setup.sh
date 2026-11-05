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

echo "[i] Using $(go version)"
echo "[i] Downloading dependencies..."
go mod download

echo "[i] Building bin/fvault..."
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/fvault ./cmd/fvault

echo
echo "[OK] Build complete: $(pwd)/bin/fvault"
echo
echo "Next steps:"
echo "  ./scripts/install.sh   # install for 'fvault start' from anywhere"
echo "  ./bin/fvault start     # or run directly from this directory"
echo
echo "The first run creates the vault and asks for your username and Master Password."
