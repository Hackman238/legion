#!/bin/sh
# Native macOS launcher: no apt, no X11, no root GUI.
# Creates .venv with Homebrew Python (3.15 preferred, see .python-version;
# Legion requires >= 3.12), installs requirements.txt when it changes,
# then runs Legion on the native Cocoa Qt platform. Pass through any
# Legion flags, e.g.:  ./startLegion-macos.sh --web --web-port 5000
# Use `setup` to (re)create the environment, reinstall and prime caches:
#   ./startLegion-macos.sh setup
# External scan tools are optional and resolved from PATH at run time:
#   brew install nmap nikto hydra sqlmap sslscan dnsmap  # as needed
set -eu
cd "$(dirname "$0")"

py_ok() {
    command -v "$1" >/dev/null 2>&1 || return 1
    "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null
}

PY=""
# Prefer the newest pinned brews first, then any python3 >= 3.12.
for c in python3.15 python3.14 python3.13 python3.12 python3; do
    if py_ok "$c"; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
    echo "Python 3.12+ not found. Install it with: brew install python@3.15" >&2
    exit 1
fi

SETUP=0
[ "${1:-}" = "setup" ] && SETUP=1

if [ "$SETUP" = "1" ] || [ ! -x .venv/bin/python ] || \
   ! .venv/bin/python -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
    rm -rf .venv
    "$PY" -m venv .venv
    rm -f .venv/.requirements.sha256
fi

REQ_HASH=$(shasum -a 256 requirements.txt | cut -d' ' -f1)
if [ "$SETUP" = "1" ] || [ ! -f .venv/.requirements.sha256 ] || \
   [ "$(cat .venv/.requirements.sha256 2>/dev/null)" != "$REQ_HASH" ]; then
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -r requirements.txt
    printf '%s' "$REQ_HASH" > .venv/.requirements.sha256
fi

if [ "$SETUP" = "1" ]; then
    # Prime the local ExploitDB cache (same as the Linux installer);
    # non-fatal if the network is unavailable.
    .venv/bin/python primeExploitDb.py || \
        echo "ExploitDB priming skipped/failed; CVE data may be empty until it succeeds." >&2
    echo "Setup complete. Run: ./startLegion-macos.sh [--web]"
    exit 0
fi

# Homebrew tools for both Apple Silicon and Intel prefixes.
PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export PATH
exec .venv/bin/python legion.py "$@"
