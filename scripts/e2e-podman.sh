#!/usr/bin/env bash
# Podman deployment e2e — fixtures the manual podman bring-up.
#
# Run ON the podman host as a user with `sudo podman`. Builds the unified
# image, brings up control + relay + a node container via deploy/fluxpeer-podman,
# verifies the node creates its TUN + enrolls active at the control, then tears down.
#
#   scripts/e2e-podman.sh [--keep]
#
# Node containers need a TUN, which rootless podman can't grant — so the driver runs
# under `sudo podman` here (control/relay don't strictly need it, but we keep one
# podman root namespace for a clean teardown).
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMAGE=localhost/fluxpeer:latest
export FLUXPEER_IMAGE=$IMAGE
export FLUXPEER_OCI_RUNTIME=${FLUXPEER_OCI_RUNTIME:-crun}
DRV=(sudo -E ./deploy/fluxpeer-podman)
ADMIN=podman-e2e
# High, uncommon ports — in case the host is shared with other projects' containers.
# Don't collide with them. Override via env if needed.
PORT=${FLUXPEER_E2E_PORT:-28080}
RELAY_PORT=${FLUXPEER_E2E_RELAY_PORT:-23478}
NODE=e2enode
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

QAIP=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^(192\.168|10\.[0-9])' | head -1)
S="http://127.0.0.1:$PORT"

say() { echo; echo "━━━ $* ━━━"; }
fail() { echo "✗ FAIL: $*"; cleanup; exit 1; }

cleanup() {
  [ "$KEEP" = 1 ] && { echo "(--keep: leaving containers up)"; return; }
  say "cleanup"
  "${DRV[@]}" rm "$NODE"    >/dev/null 2>&1 || true
  "${DRV[@]}" rm control    >/dev/null 2>&1 || true
  "${DRV[@]}" rm relay      >/dev/null 2>&1 || true
  rm -f fp-bin-tmp
}
trap cleanup EXIT

[ -n "$QAIP" ] || fail "no LAN IP (needed so the node container reaches the published control port)"
command -v sudo >/dev/null && sudo -n podman version >/dev/null 2>&1 || fail "need passwordless 'sudo podman' on this host"
echo "podman host IP: $QAIP   runtime: $FLUXPEER_OCI_RUNTIME"

say "ensure image $IMAGE (quick build from the prebuilt musl binary)"
if ! sudo podman image exists "$IMAGE" 2>/dev/null; then
  BIN=target/x86_64-unknown-linux-musl/release/fluxpeer
  [ -f "$BIN" ] || fail "no musl binary at $BIN (build it: cargo build --release --target x86_64-unknown-linux-musl -p fluxpeer)"
  cp -f "$BIN" ./fp-bin-tmp
  printf 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables ca-certificates iputils-ping && rm -rf /var/lib/apt/lists/*\nCOPY fp-bin-tmp /usr/local/bin/fluxpeer\nENTRYPOINT ["/usr/local/bin/fluxpeer"]\n' > /tmp/fp-cf.quick
  sudo podman build -q -f /tmp/fp-cf.quick -t "$IMAGE" . >/dev/null || fail "image build"
  echo "✓ built $IMAGE"
else
  echo "✓ image present"
fi

say "fresh state — remove any leftover containers"
for c in "$NODE" control relay; do "${DRV[@]}" rm "$c" >/dev/null 2>&1 || true; done

say "up control + relay"
"${DRV[@]}" up control --port "$PORT" --admin-password "$ADMIN" >/dev/null || fail "up control"
"${DRV[@]}" up relay --port "$RELAY_PORT" >/dev/null || fail "up relay"
curl --retry 20 --retry-connrefused --retry-delay 1 -s "$S/api/v1/health" | grep -q ok || fail "control not healthy"
echo "✓ control + relay containers up; control healthy"

say "create network + invite, build a join token (ctrl = host published port)"
NET=$(curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'content-type: application/json' "$S/api/v1/networks" -d '{"name":"podman-e2e"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])') || fail "create network"
INV=$(curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'content-type: application/json' "$S/api/v1/networks/$NET/invites" -d '{}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["code"])')
TOK="fp://join/$(python3 -c "import base64,json;print(base64.urlsafe_b64encode(json.dumps({'ctrl':'http://$QAIP:$PORT','code':'$INV'}).encode()).decode().rstrip('='))")"

say "join a node (enroll + node container with NET_ADMIN + /dev/net/tun)"
"${DRV[@]}" join "$TOK" "$NODE" --port 41820 >/dev/null || fail "join node"
sleep 5

say "verify: node container running + fp0 TUN + active at control"
sudo podman ps --filter "name=fluxpeer-node-$NODE" --format '{{.Names}} {{.Status}}' | grep -q Up || fail "node container not running"
echo "✓ node container running"
sudo podman exec "fluxpeer-node-$NODE" ip -br addr show fp0 2>/dev/null | grep -qE '100\.(64|72)\.' || fail "node has no fp0 overlay address"
ADDR=$(sudo podman exec "fluxpeer-node-$NODE" sh -c "ip -4 addr show fp0 | grep -oE '100\.[0-9.]+' | head -1" 2>/dev/null)
echo "✓ node fp0 TUN up ($ADDR)"
curl -s -H "Authorization: Bearer $ADMIN" "$S/api/v1/networks/$NET/devices" | python3 -c 'import sys,json;d=json.load(sys.stdin);assert any(x["status"]=="active" for x in d),"no active device";print("✓ control sees device active:",[x["address_v4"] for x in d])' || fail "device not active at control"

say "RESULT"
echo "✓ Podman deployment e2e PASSED (control + relay + node containers; node $ADDR enrolled active)"
