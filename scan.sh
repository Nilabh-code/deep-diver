#!/usr/bin/env bash
# deep-diver one-shot: ./scan.sh <URL> [extra deepdiver args...]
# examples:
#   ./scan.sh https://example.com
#   ./scan.sh https://example.com --budget 90 --mode normal
#   ./scan.sh https://example.com --recon-only
#   ./scan.sh https://example.com --cred-email test@x.com --cred-password 'pw'
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PATH:$HOME/go/bin"

if [[ $# -lt 1 ]]; then
  echo "usage: ./scan.sh <URL> [--budget N] [--mode quiet|normal|aggressive] [--recon-only] [--cred-email E --cred-password P]"
  exit 1
fi
exec uv run deepdiver run "$@"
