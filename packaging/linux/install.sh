#!/usr/bin/env bash
# Install the fluxpeer daemon as a systemd service. Run with sudo.
# Build the static binary on your build host first (musl recommended), then:
#   sudo packaging/linux/install.sh /path/to/fluxpeer
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
UNIT_SRC="$HERE/fluxpeer.service"
UNIT_DST="/etc/systemd/system/fluxpeer.service"
BIN_DST="/usr/local/bin/fluxpeer"

if [[ $EUID -ne 0 ]]; then echo "run with sudo" >&2; exit 1; fi

BIN_SRC="${1:-}"
[[ -z "$BIN_SRC" && -x "$HERE/fluxpeer" ]] && BIN_SRC="$HERE/fluxpeer"
[[ -z "$BIN_SRC" ]] && BIN_SRC="$(command -v fluxpeer || true)"
if [[ -z "$BIN_SRC" || ! -x "$BIN_SRC" ]]; then
  echo "usage: sudo $0 /path/to/fluxpeer" >&2; exit 1
fi

echo "==> installing $BIN_SRC -> $BIN_DST"
install -m 0755 "$BIN_SRC" "$BIN_DST"
mkdir -p /etc/fluxpeer && chmod 0755 /etc/fluxpeer

echo "==> installing systemd unit"
install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable --now fluxpeer.service

echo "done. Status: systemctl status fluxpeer"
echo "Join a network: sudo fluxpeer join 'fp://join/…'  (the daemon picks it up)"
echo "GUI reads the token at /etc/fluxpeer/daemon.token."
