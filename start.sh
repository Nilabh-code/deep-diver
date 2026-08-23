#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PATH:$HOME/go/bin"
exec uv run deepdiver serve --port "${1:-8911}"
