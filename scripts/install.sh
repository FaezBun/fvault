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

BIN_DIR="${FVAULT_BIN_DIR:-$HOME/.local/bin}"
SHARE_ROOT="${FVAULT_SHARE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/fvault}"

echo "[i] Building..."
./scripts/build.sh

echo "[i] Installing binary to $BIN_DIR/fvault"
mkdir -p "$BIN_DIR"
install -m 755 bin/fvault "$BIN_DIR/fvault"

echo "[i] Installing web assets to $SHARE_ROOT"
mkdir -p "$SHARE_ROOT"
rm -rf "$SHARE_ROOT/templates" "$SHARE_ROOT/static"
cp -R templates "$SHARE_ROOT/templates"
cp -R static "$SHARE_ROOT/static"

echo
echo "[OK] Installed fvault"
echo "     binary : $BIN_DIR/fvault"
echo "     assets : $SHARE_ROOT"
echo
case ":$PATH:" in
  *":$BIN_DIR:"*)
    echo "Run: fvault start"
    ;;
  *)
    echo "$BIN_DIR is not in your PATH."
    echo "Add this line to your shell profile:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    echo "Then run: fvault start"
    ;;
esac
