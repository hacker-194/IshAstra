#!/usr/bin/env bash
# Compatibility wrapper. The real checks live in production_preflight.py so the
# validator is tested and cannot drift from the application's startup rules.
#
# Usage: ./scripts/validate-env.sh [--env-file FILE] [--scope-file FILE]
#          [--backup-dir DIR] [--tls-enabled] [--allow-sqlite] [--skip-db]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/production_preflight.py" "$@"
