#!/usr/bin/env bash
# e2e-device-token.sh — server-contract regression for the per-device bearer that
# closes the unauthenticated guessable-`dev-N` IDOR. Black-box over real HTTP (no
# netns). Proves GET /devices/:id/gateway is token-gated:
#   * no bearer            → 401
#   * garbage bearer       → 401
#   * ANOTHER device token → 401   (the IDOR itself)
#   * the device's OWN tok → not 401  (200 or 404 if no gateway configured)
#   * admin master bearer  → not 401  (admin may act on any device)
# Build the binary on a Linux host (musl); run anywhere.
set -u
B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
D="${FLUXPEER_E2E_DIR:-/tmp/fp-devtok}"
CPORT="${FLUXPEER_E2E_PORT:-18093}"
ADMIN="${FLUXPEER_ADMIN_PASSWORD:-reg}"
CTRL="http://127.0.0.1:$CPORT"
pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }
teardown(){ pkill -f "$B control" 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$D"; }
trap teardown EXIT
teardown 2>/dev/null; sleep 1; mkdir -p "$D/cfg"

# GET /devices/:id/gateway, optional bearer; echoes the HTTP status code.
code(){ # $1=device_id  $2=bearer(optional)
  if [ -n "${2:-}" ]; then
    curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $2" "$CTRL/api/v1/devices/$1/gateway"
  else
    curl -s -o /dev/null -w '%{http_code}' "$CTRL/api/v1/devices/$1/gateway"
  fi
}

echo "===== start SQL control ====="
DATABASE_URL="sqlite://$D/db.sqlite?mode=rwc" FLUXPEER_CONTROL_ADDR=0.0.0.0:$CPORT FLUXPEER_ADMIN_PASSWORD="$ADMIN" \
  nohup "$B" control >"$D/control.log" 2>&1 & sleep 2
curl -s "$CTRL/health" >/dev/null && ok "control up" || { no "control down"; sed 's/^/    /' "$D/control.log"; echo "RESULTS: $pass/$fail"; exit 1; }
export FLUXPEER_CONTROL_URL="$CTRL" FLUXPEER_ADMIN_PASSWORD="$ADMIN"

echo "===== network + enroll two devices ====="
"$B" ctl --server "$CTRL" network create tok >/dev/null 2>&1
NID=$("$B" ctl --server "$CTRL" network list 2>/dev/null | grep -oE 'net-[0-9]+' | head -1)
mktok(){ local c; c=$("$B" ctl --server "$CTRL" invite create "$NID" 2>/dev/null | grep -oE '[0-9a-f]{32}' | head -1)
  python3 -c "import json,base64;print('fp://join/'+base64.urlsafe_b64encode(json.dumps({'ctrl':'$CTRL','code':'$c'}).encode()).decode().rstrip('='))"; }
"$B" join "$(mktok)" --out "$D/cfg/A.json" --no-run --name devA 2>&1 | grep -q enrolled && ok "device A enrolled" || no "A enroll"
"$B" join "$(mktok)" --out "$D/cfg/B.json" --no-run --name devB 2>&1 | grep -q enrolled && ok "device B enrolled" || no "B enroll"
jget(){ python3 -c "import json;print(json.load(open('$1')).get('$2',''))"; }
IDA=$(jget "$D/cfg/A.json" device_id); TOKA=$(jget "$D/cfg/A.json" auth_token)
IDB=$(jget "$D/cfg/B.json" device_id); TOKB=$(jget "$D/cfg/B.json" auth_token)
{ [ -n "$IDA" ] && [ -n "$TOKA" ]; } && ok "A has device_id+auth_token" || no "A missing id/token (id=$IDA tok=${TOKA:+set})"
[ -n "$TOKB" ] && ok "B has auth_token" || no "B missing token"

echo "===== assert /devices/:id/gateway auth contract ====="
c=$(code "$IDA" "");       [ "$c" = 401 ]  && ok "no-bearer → 401"             || no "no-bearer expected 401 got $c"
c=$(code "$IDA" "deadbeef");[ "$c" = 401 ] && ok "garbage-bearer → 401"        || no "garbage expected 401 got $c"
c=$(code "$IDA" "$TOKB");  [ "$c" = 401 ]  && ok "IDOR: B-token on A → 401"    || no "IDOR expected 401 got $c"
c=$(code "$IDA" "$TOKA");  [ "$c" != 401 ] && ok "own token → not 401 ($c)"    || no "own token got 401"
c=$(code "$IDA" "$ADMIN"); [ "$c" != 401 ] && ok "admin master → not 401 ($c)" || no "admin master got 401"

echo "===== RESULTS: $pass pass / $fail fail ====="
[ "$fail" = 0 ]
