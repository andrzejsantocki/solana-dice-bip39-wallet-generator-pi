#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
REQ="$ROOT/requirements-hashes.txt"
PKGS="$ROOT/pkgs"
PYTHON_BIN="${PYTHON_BIN:-python3}"

"$PYTHON_BIN" - <<'PY'
import platform, struct, sys
assert sys.version_info[:2] == (3, 11), 'Requires CPython 3.11 for bundled Raspberry Pi wheels'
assert struct.calcsize('P') * 8 == 64, 'Requires 64-bit Python'
assert platform.machine().lower() in ('aarch64', 'arm64'), 'Requires Raspberry Pi OS 64-bit / aarch64'
print(sys.version)
print(platform.machine())
PY

if [ ! -x "$VENV/bin/python" ]; then
  "$PYTHON_BIN" -m venv "$VENV"
fi

"$VENV/bin/python" - <<'PY'
import platform, struct, sys
assert sys.version_info[:2] == (3, 11), 'Venv must use Python 3.11. Delete .venv and rerun setup_env.sh.'
assert struct.calcsize('P') * 8 == 64, 'Venv must be 64-bit.'
assert platform.machine().lower() in ('aarch64', 'arm64'), 'Venv must run on aarch64/arm64.'
print(sys.version)
PY

if [ ! -d "$PKGS" ]; then
  echo "Missing pkgs folder. Refusing online install." >&2
  exit 1
fi

"$VENV/bin/python" -m pip install --no-index --find-links="$PKGS" --require-hashes -r "$REQ"

echo
echo "Ready. Venv: $VENV"
echo "Run self-test: $VENV/bin/python -I generate_wallet.py --self-test"
echo "Run wallet:    $VENV/bin/python -I generate_wallet.py"
