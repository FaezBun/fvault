#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export FVAULT_HOME="${FVAULT_HOME:-$PWD/data}"

if [ ! -x bin/fvault ]; then
  ./scripts/build.sh
fi

if [ "$#" -eq 0 ]; then
  exec ./bin/fvault menu
fi

exec ./bin/fvault "$@"
