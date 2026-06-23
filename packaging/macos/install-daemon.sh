#!/usr/bin/env bash
# Install the fluxpeer daemon as a macOS LaunchDaemon (runs as root for the TUN
# device). Run with sudo. Expects a `fluxpeer` binary next to this script or on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PLIST_SRC="$HERE/org.fluxpeer.daemon.plist"
PLIST_DST="/Library/LaunchDaemons/org.fluxpeer.daemon.plist"
BIN_DST="/usr/local/bin/fluxpeer"

if [[ $EUID -ne 0 ]]; then echo "run with sudo" >&2; exit 1; fi

# Locate the binary: arg1, sibling ./fluxpeer, or PATH.
BIN_SRC="${1:-}"
[[ -z "$BIN_SRC" && -x "$HERE/fluxpeer" ]] && BIN_SRC="$HERE/fluxpeer"
[[ -z "$BIN_SRC" ]] && BIN_SRC="$(command -v fluxpeer || true)"
if [[ -z "$BIN_SRC" || ! -x "$BIN_SRC" ]]; then
  echo "usage: sudo $0 /path/to/fluxpeer   (or place the binary next to this script)" >&2
  exit 1
fi

echo "==> installing $BIN_SRC -> $BIN_DST"
install -m 0755 "$BIN_SRC" "$BIN_DST"
mkdir -p /etc/fluxpeer && chmod 0755 /etc/fluxpeer

echo "==> installing LaunchDaemon"
install -m 0644 "$PLIST_SRC" "$PLIST_DST"
launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl load -w "$PLIST_DST"

echo "done. daemon runs at boot. Join a network with:"
echo "    sudo fluxpeer join 'fp://join/…'"
echo "GUI reads the token at /etc/fluxpeer/daemon.token."
