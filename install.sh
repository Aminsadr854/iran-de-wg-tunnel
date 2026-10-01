#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo 'Python 3 is required (apt install python3).' >&2; exit 1; }
exec python3 "$ROOT/scripts/tunnelctl.py" install "$@"
