#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
for script in install.sh uninstall.sh tests/run.sh; do
    bash -n "$script"
done
if command -v shellcheck >/dev/null; then
    shellcheck install.sh uninstall.sh tests/run.sh
else
    echo 'ShellCheck unavailable; bash syntax still checked.'
fi
python3 -m unittest discover -s tests -p 'test_*.py' -v
./install.sh --dry-run --offline --config config.example.env >/dev/null
./install.sh --dry-run --offline --role iran >/dev/null
