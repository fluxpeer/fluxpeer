#!/usr/bin/env bash
# Install the fluxpeer daemon as a macOS LaunchDaemon (runs as root for the TUN
# device). Run with sudo. Expects a `fluxpeer` binary next to this script or on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PLIST_SRC="$HERE/org.fluxpeer.daemon.plist"
PLIST_DST="/Library/LaunchDaemons/org.fluxpeer.daemon.plist"
BIN_DST="/usr/local/bin/fluxpeer"
CONFIG_DIR="/etc/fluxpeer"
TOKEN="$CONFIG_DIR/daemon.token"

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
mkdir -p "$CONFIG_DIR" && chmod 0755 "$CONFIG_DIR"

echo "==> installing LaunchDaemon"
install -m 0644 "$PLIST_SRC" "$PLIST_DST"
launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl load -w "$PLIST_DST"

# The daemon token is a local control credential for the root daemon: it lets the
# desktop client list/join/connect/disconnect/leave networks and read redacted
# config. High-risk raw config mutation/shutdown verbs are still disabled unless
# the daemon is explicitly started with FLUXPEER_ALLOW_ADMIN_API=1.
TOKEN_USER="${FLUXPEER_DAEMON_TOKEN_USER:-${SUDO_USER:-root}}"
TOKEN_GROUP="$(id -gn "$TOKEN_USER" 2>/dev/null || echo wheel)"
for _ in {1..20}; do
  [[ -f "$TOKEN" ]] && break
  sleep 0.25
done
if [[ -f "$TOKEN" ]]; then
  chown "$TOKEN_USER:$TOKEN_GROUP" "$TOKEN" 2>/dev/null || chown root:wheel "$TOKEN"
  chmod 0600 "$TOKEN"
  echo "==> daemon token owner: $TOKEN_USER:$TOKEN_GROUP, mode: 0600"
else
  echo "==> daemon token not created yet; when it appears, set owner/group deliberately and chmod 0600: $TOKEN"
fi

echo "done. daemon runs at boot. Join a network with:"
echo "    sudo fluxpeer join 'fp://join/…'"
echo "GUI reads the local daemon control token at $TOKEN."
