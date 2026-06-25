#!/usr/bin/env bash
# e2e-android-node.sh — mobile end-to-end over the REAL node engine.
#
# As of `feat(mobile): run the full node engine on Android`, the phone runs the
# full fluxpeer node (magicsock + disco), NOT the old "dispatcher" client. So it
# peers with a REAL `fluxpeer node` gateway — exactly the node↔node path that
# e2e-wan.sh exercises. The retired `examples/mobilegw` (a dispatcher server) is
# NOT protocol-compatible with the current phone and must not be used.
#
# This harness automates the SERVER side and the client-enroll, then verifies the
# data plane from the phone over adb:
#   1. (alignment) require a LOCALLY-BUILT musl `fluxpeer` from the current HEAD
#      — client APK and server/node MUST come from the same commit (see docs/CI.md).
#   2. start control + relay(+STUN) on the gateway host.
#   3. enroll a gateway device (PoP) and run `fluxpeer node run` as the gateway —
#      it advertises its public endpoint so the phone resolves it as its gateway.
#   4. enroll the phone's wg key (PoP, via scripts/lib/fp_enroll.py) so the phone's
#      device has a valid per-device bearer (the IDOR fix requires it).
#   5. phone connects (app UI / appium) → assert ping + HTTP over the overlay.
#
#   scripts/e2e-android-node.sh \
#     --gw-host <ssh-host> --gw-pub <ip:port advertised> \
#     --phone-priv <hex> [--phone-pub <hex>] \
#     [--bin target/x86_64-unknown-linux-musl/release/fluxpeer] [--adb-serial <id>] [--keep]
#
# The phone's wg private key lives in the app (fluxpeer_networks.xml: client_prikey).
# For a fully manual run, omit --phone-priv and join via the app's token instead.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="scripts/lib"

BIN="${FLUXPEER_BIN:-target/x86_64-unknown-linux-musl/release/fluxpeer}"
GW_HOST="" ; GW_PUB="" ; PHONE_PRIV="" ; PHONE_PUB="" ; ADB_SERIAL="" ; KEEP=0
ADMIN="${FLUXPEER_ADMIN_PASSWORD:-regtest}"
CPORT="${FLUXPEER_E2E_PORT:-8090}" ; RPORT="${FLUXPEER_E2E_RELAY_PORT:-3478}" ; GWPORT="${FLUXPEER_E2E_GW_PORT:-41822}"
while [ $# -gt 0 ]; do case "$1" in
  --gw-host) GW_HOST="$2"; shift 2;; --gw-pub) GW_PUB="$2"; shift 2;;
  --phone-priv) PHONE_PRIV="$2"; shift 2;; --phone-pub) PHONE_PUB="$2"; shift 2;;
  --bin) BIN="$2"; shift 2;; --adb-serial) ADB_SERIAL="$2"; shift 2;; --keep) KEEP=1; shift;;
  *) echo "unknown arg: $1" >&2; exit 2;; esac; done
[ -n "$GW_HOST" ] && [ -n "$GW_PUB" ] || { echo "need --gw-host and --gw-pub (see header)" >&2; exit 2; }

SSH=(ssh -n -o ProxyCommand=none -o ConnectTimeout=15)
ADB=(adb); [ -n "$ADB_SERIAL" ] && ADB=(adb -s "$ADB_SERIAL")
GWIP="${GW_PUB%%:*}"; CTRL="http://$GWIP:$CPORT"
say(){ echo; echo "━━━ $* ━━━"; }
fail(){ echo "✗ FAIL: $*" >&2; exit 1; }

# --- alignment gate ---
say "alignment: locally-built binary from current HEAD"
[ -f "$BIN" ] || fail "no binary at $BIN — build it from THIS HEAD: cargo zigbuild --release --target x86_64-unknown-linux-musl -p fluxpeer (and the APK from the same commit; see docs/CI.md)"
echo "HEAD=$(git rev-parse --short HEAD 2>/dev/null)  bin=$BIN"

# --- ship binary + bring up control/relay/gateway-node on GW_HOST ---
say "deploy binary to $GW_HOST (binary only — never source on a node)"
scp -q "$BIN" "$GW_HOST:/tmp/fluxpeer-e2e" || fail "scp binary"
"${SSH[@]}" "$GW_HOST" "chmod +x /tmp/fluxpeer-e2e"

say "start control + relay(+STUN)"
"${SSH[@]}" "$GW_HOST" "setsid bash -c 'rm -f /tmp/fpe2e-control.db; DATABASE_URL=\"sqlite:///tmp/fpe2e-control.db?mode=rwc\" FLUXPEER_CONTROL_ADDR=0.0.0.0:$CPORT FLUXPEER_ADMIN_PASSWORD=$ADMIN /tmp/fluxpeer-e2e control >/tmp/fpe2e-control.log 2>&1' </dev/null >/dev/null 2>&1 &"
"${SSH[@]}" "$GW_HOST" "setsid bash -c 'FLUXPEER_RELAY_ADDR=0.0.0.0:$RPORT FLUXPEER_RELAY_STUN=0.0.0.0:$RPORT /tmp/fluxpeer-e2e relay >/tmp/fpe2e-relay.log 2>&1' </dev/null >/dev/null 2>&1 &"
sleep 4
curl -s -o /dev/null -w '%{http_code}' "$CTRL/api/v1/networks" -H "Authorization: Bearer $ADMIN" | grep -q 200 || fail "control not reachable at $CTRL"

say "create network + invite"
"${SSH[@]}" "$GW_HOST" "FLUXPEER_CONTROL_URL=$CTRL FLUXPEER_ADMIN_PASSWORD=$ADMIN /tmp/fluxpeer-e2e ctl --server $CTRL network create e2e" >/dev/null 2>&1 || true
NID=$("${SSH[@]}" "$GW_HOST" "/tmp/fluxpeer-e2e ctl --server $CTRL network list" 2>/dev/null | grep -oE 'net-[0-9]+' | head -1)
CODE=$("${SSH[@]}" "$GW_HOST" "/tmp/fluxpeer-e2e ctl --server $CTRL invite create $NID" 2>/dev/null | grep -oE '[0-9a-f]{32}' | head -1)
[ -n "$CODE" ] || fail "no invite code"; echo "network=$NID invite=$CODE"

say "enroll + run the gateway node (PoP)"
GWPRIV=$("${SSH[@]}" "$GW_HOST" "/tmp/fluxpeer-e2e node keygen" 2>/dev/null | grep -oE 'private_key = [0-9a-f]+' | awk '{print $3}')
GWDEV=$(python3 "$HERE/fp_enroll.py" "$CTRL" "$CODE" "e2e-gateway" "$GWPRIV")
GWID=$(echo "$GWDEV" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
GWTOK=$(echo "$GWDEV" | python3 -c 'import json,sys;print(json.load(sys.stdin)["auth_token"])')
GWOV=$(echo "$GWDEV" | python3 -c 'import json,sys;print(json.load(sys.stdin)["address_v4"])')
echo "gateway device=$GWID overlay=$GWOV"
"${SSH[@]}" "$GW_HOST" "cat > /tmp/fpe2e-node.json <<JSON
{\"control_server\":\"$CTRL\",\"device_id\":\"$GWID\",\"auth_token\":\"$GWTOK\",\"listen_port\":$GWPORT,\"prefix_len\":24,\"private_key\":\"$GWPRIV\",\"tun_name\":\"fp0\",\"advertise\":[\"$GW_PUB\"]}
JSON"
"${SSH[@]}" "$GW_HOST" "sudo nohup setsid /tmp/fluxpeer-e2e node run /tmp/fpe2e-node.json >/tmp/fpe2e-node.log 2>&1 </dev/null &"
sleep 5
"${SSH[@]}" "$GW_HOST" "ip -br a | grep -q '$GWOV' " || fail "gateway node TUN did not come up ($GWOV)"
echo "gateway node up on $GW_PUB → overlay $GWOV"

# --- phone enroll ---
JOIN_TOKEN=$(python3 -c "import json,base64;print('fp://join/'+base64.urlsafe_b64encode(json.dumps({'ctrl':'$CTRL','code':'$CODE'}).encode()).decode().rstrip('='))")
if [ -n "$PHONE_PRIV" ]; then
  say "enroll the phone's wg key (PoP) so its device has a valid bearer"
  PHDEV=$(python3 "$HERE/fp_enroll.py" "$CTRL" "$CODE" "e2e-phone" "$PHONE_PRIV" ${PHONE_PUB:+$PHONE_PUB})
  PHID=$(echo "$PHDEV" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')
  PHTOK=$(echo "$PHDEV" | python3 -c 'import json,sys;print(json.load(sys.stdin)["auth_token"])')
  PHOV=$(echo "$PHDEV" | python3 -c 'import json,sys;print(json.load(sys.stdin)["address_v4"])')
  echo "phone device=$PHID overlay=$PHOV token=$PHTOK"
  echo "→ patch the app's network (fluxpeer_networks.xml): deviceId=$PHID auth_token=$PHTOK overlayV4=$PHOV"
fi
echo
echo "MANUAL: on the phone, connect the network (join token below if not enrolled), then this script verifies:"
echo "  join token: $JOIN_TOKEN"

# --- verify data plane from the phone over adb (ping + HTTP over the overlay) ---
say "verify: phone → gateway overlay $GWOV (ping + HTTP over mesh)"
"${SSH[@]}" "$GW_HOST" "echo fluxpeer-mesh-ok > /tmp/fpe2e-probe.txt; setsid nohup python3 -m http.server 8088 --bind $GWOV >/tmp/fpe2e-http.log 2>&1 </dev/null &" || true
echo "waiting for the phone tunnel… (connect it now)"; for i in $(seq 1 30); do
  if "${ADB[@]}" shell ping -c 1 -W 2 "$GWOV" >/dev/null 2>&1; then break; fi; sleep 2; done
PING=$("${ADB[@]}" shell ping -c 5 -W 3 "$GWOV" 2>&1 | grep -oE '[0-9]+% packet loss' | head -1)
echo "ping: ${PING:-no reply}"
HTTP=$("${ADB[@]}" shell 'printf "GET /fpe2e-probe.txt HTTP/1.0\r\nHost: h\r\n\r\n" | toybox nc -w 6 '"$GWOV"' 8088' 2>&1 | grep -c "fluxpeer-mesh-ok")
echo "http-over-mesh: $([ "$HTTP" = 1 ] && echo OK || echo FAIL)"

if [ "$KEEP" = 0 ]; then
  say "cleanup (--keep to skip)"
  "${SSH[@]}" "$GW_HOST" "sudo pkill -f 'fluxpeer-e2e node run'; pkill -f 'fluxpeer-e2e control'; pkill -f 'fluxpeer-e2e relay'; pkill -f 'http.server 8088'; sudo ip link del fp0 2>/dev/null; rm -f /tmp/fpe2e-* /tmp/fluxpeer-e2e" 2>/dev/null || true
fi
[ "${PING:-}" = "0% packet loss" ] && [ "${HTTP:-0}" = 1 ] && { echo; echo "✓ PASS: android e2e over real node ($GWOV)"; exit 0; }
echo; echo "✗ data-plane not verified (ensure the phone connected during the wait window)"; exit 1
