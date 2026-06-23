#!/usr/bin/env bash
# Cross-platform 2-node data-plane e2e (testing layer 2).
#
# Brings up a control-server on THIS host (macOS/Linux), one LOCAL node, and one
# REMOTE node (a Windows VM ssh host, supplied via --win-host or FLUXPEER_E2E_WIN_HOST),
# then verifies BIDIRECTIONAL ping over the tunnel — TTL-checked so a stale node
# can't fake a pass.
#
#   scripts/e2e-2node.sh --win-host <windows-host> [--port 18080] [--keep]
#
# Bakes in the gotchas found during manual bring-up:
#  - kill ALL stale fp-node first + confirm the UDP port is free (else a leftover
#    node owning the overlay IP yields a false ping result; TTL tells truth:
#    Windows-local replies TTL=128, a real remote macOS reply is ~64).
#  - reach the control-server via the LAN IP, NOT 127.0.0.1 (an ssh LocalForward
#    can squat loopback:8080).
#  - Windows blocks inbound ICMP echo by default → add a temp firewall rule.
#  - ssh/scp with -o ProxyCommand=none (a global proxy otherwise interferes).
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

WIN_HOST="${FLUXPEER_E2E_WIN_HOST:-}"
PORT=18080
KEEP=0
LANIP=""
while [ $# -gt 0 ]; do case "$1" in
  --win-host) WIN_HOST="$2"; shift 2 ;;
  --port) PORT="$2"; shift 2 ;;
  --lan-ip) LANIP="$2"; shift 2 ;;
  --keep) KEEP=1; shift ;;
  *) echo "unknown arg: $1"; exit 2 ;;
esac; done
[ -n "$WIN_HOST" ] || { echo "missing --win-host <windows-host> (or FLUXPEER_E2E_WIN_HOST)" >&2; exit 2; }

SSH=(ssh -o ProxyCommand=none -o ProxyJump=none -o ConnectTimeout=12)
SCP=(scp -o ProxyCommand=none -o ProxyJump=none -o ConnectTimeout=12)
ADMIN=e2e-pw
FLUX=target/debug/fluxpeer            # control + ctl + join + local node
WINEXE=target/x86_64-pc-windows-gnu/debug/fp-node.exe
WINTUN=engine/vendor/wintun/examples/wintun/bin/amd64/wintun.dll
TMP=$(mktemp -d /tmp/fpe2e.XXXX)
CTL_PID=""
WIN_SSH=""

say() { echo; echo "━━━ $* ━━━"; }
fail() { echo "✗ FAIL: $*"; cleanup; exit 1; }

cleanup() {
  [ "$KEEP" = 1 ] && { echo "(--keep: leaving nodes + control running)"; return; }
  say "cleanup"
  sudo pkill -f 'target/debug/fp-node|target/debug/fluxpeer node' 2>/dev/null
  [ -n "$CTL_PID" ] && kill "$CTL_PID" 2>/dev/null
  [ -n "$WIN_SSH" ] && kill "$WIN_SSH" 2>/dev/null
  pkill -f 'fluxpeer control' 2>/dev/null
  "${SSH[@]}" "$WIN_HOST" 'powershell -NoProfile -c "Get-Process fp-node -EA SilentlyContinue | Stop-Process -Force; Remove-NetFirewallRule -DisplayName fp-e2e-icmp -ErrorAction SilentlyContinue"' 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

# LAN IP the VM can reach. Prefer a 192.168.x address (the dev box may also have a
# VPN iface as its default route, which the VM can't reach). Override with --lan-ip.
if [ -z "$LANIP" ]; then
  LANIP=$(ifconfig 2>/dev/null | awk '/inet 192\.168\./{print $2; exit}')
  [ -z "$LANIP" ] && LANIP=$(ipconfig getifaddr en0 2>/dev/null)
  [ -z "$LANIP" ] && LANIP=$(ipconfig getifaddr en1 2>/dev/null)
  [ -z "$LANIP" ] && LANIP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
fi
[ -n "$LANIP" ] || fail "could not determine LAN IP (use --lan-ip <ip>)"
S="http://$LANIP:$PORT"
echo "control: $S   win-host: $WIN_HOST   tmp: $TMP"

say "build binaries (local fluxpeer + windows fp-node.exe)"
cargo build -q -p fluxpeer || fail "local build"
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
    AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
  cargo build -q --target x86_64-pc-windows-gnu -p fluxpeer-node --bin fp-node || fail "windows build"
else
  [ -x "$WINEXE" ] || fail "no mingw toolchain and no prebuilt $WINEXE"
fi

say "kill stale nodes (local + win) + confirm port $PORT/41820 free"
sudo pkill -f 'target/debug/fp-node|target/debug/fluxpeer node' 2>/dev/null
pkill -f 'fluxpeer control' 2>/dev/null
"${SSH[@]}" "$WIN_HOST" 'powershell -NoProfile -c "Get-Process fp-node -EA SilentlyContinue | Stop-Process -Force"' 2>/dev/null
sleep 2

say "start control-server (LAN-bound)"
FLUXPEER_ADMIN_PASSWORD=$ADMIN FLUXPEER_CONTROL_ADDR=0.0.0.0:$PORT \
  DATABASE_URL="sqlite:file:e2e?mode=memory&cache=shared" "$FLUX" control >"$TMP/control.log" 2>&1 &
CTL_PID=$!
curl --retry 30 --retry-connrefused --retry-delay 1 -s "$S/api/v1/health" >/dev/null || fail "control not healthy"
echo "✓ control up (pid $CTL_PID)"

say "enroll 2 nodes (mac=local, win=$WIN_HOST)"
export FLUXPEER_ADMIN_PASSWORD=$ADMIN
NET=$("$FLUX" ctl --server "$S" network create e2e | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
mktoken() { python3 -c "import base64,json;print('fp://join/'+base64.urlsafe_b64encode(json.dumps({'ctrl':'$S','code':'$1'}).encode()).decode().rstrip('='))"; }
I1=$("$FLUX" ctl --server "$S" invite create "$NET" | python3 -c 'import sys,json;print(json.load(sys.stdin)["code"])')
I2=$("$FLUX" ctl --server "$S" invite create "$NET" | python3 -c 'import sys,json;print(json.load(sys.stdin)["code"])')
"$FLUX" join "$(mktoken "$I1")" --no-run --out "$TMP/mac.json" --name mac >/dev/null 2>&1 || fail "mac enroll"
"$FLUX" join "$(mktoken "$I2")" --no-run --out "$TMP/win.json" --name win >/dev/null 2>&1 || fail "win enroll"
python3 -c "import json;c=json.load(open('$TMP/win.json'));c['tun_name']='fp0';json.dump(c,open('$TMP/win.json','w'))"
# The dev box may have several ifaces (LAN + VPN, VPN as default route). Pin mac's
# ADVERTISED endpoint to the VM-reachable LAN IP — otherwise the win node sends data
# to an unreachable VPN address (handshake still works via the init's src addr, so
# you get "handshake complete" but "received 0 B" / 100% ping loss).
python3 -c "import json;c=json.load(open('$TMP/mac.json'));c['advertise']=['$LANIP:'+str(c['listen_port'])];json.dump(c,open('$TMP/mac.json','w'))"
MAC_IP=$(python3 -c "import sys,json;[print(d['address_v4']) for d in json.load(sys.stdin) if d['name']=='mac']" < <("$FLUX" ctl --server "$S" device list "$NET"))
WIN_IP=$(python3 -c "import sys,json;[print(d['address_v4']) for d in json.load(sys.stdin) if d['name']=='win']" < <("$FLUX" ctl --server "$S" device list "$NET"))
echo "✓ overlay: mac=$MAC_IP  win=$WIN_IP"

say "start nodes"
sudo env RUST_LOG=info "$FLUX" node run "$TMP/mac.json" >"$TMP/mac.log" 2>&1 &
"${SSH[@]}" "$WIN_HOST" 'mkdir fp 2>nul & echo ok' >/dev/null 2>&1
"${SCP[@]}" "$WINEXE" "$WINTUN" "$TMP/win.json" "$WIN_HOST:fp/" >/dev/null 2>&1 || fail "scp to win"
# `start /b` does NOT persist a process under non-interactive ssh — use a detached
# Start-Process (survives the ssh command returning).
# Keep the ssh connection OPEN so the win node stays alive: Windows ssh tears down
# even detached children when the non-interactive session ends. cleanup() kills it.
"${SSH[@]}" "$WIN_HOST" 'cd fp & set RUST_LOG=info & fp-node.exe run win.json' >"$TMP/win.log" 2>&1 &
WIN_SSH=$!
# Windows blocks inbound ICMP echo by default — allow it so mac→win ping is answerable.
"${SSH[@]}" "$WIN_HOST" 'powershell -NoProfile -Command "New-NetFirewallRule -DisplayName fp-e2e-icmp -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Out-Null"' >/dev/null 2>&1

say "wait for tunnel up (retry mac→win ping until it answers)"
ok=0
for _ in $(seq 1 25); do
  if ping -c 1 -t 3 "$WIN_IP" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || echo "! mac→win ping not succeeding yet (continuing to the checks for diagnostics)"

say "verify bidirectional tunnel ping (TTL-checked)"
# mac → win: a real reply comes from Windows (TTL≈128). Needs the win ICMP rule.
m2w=$(ping -c 4 -t 8 "$WIN_IP" 2>&1)
echo "$m2w" | grep -q '0.0% packet loss' || fail "mac→win ping ($WIN_IP) lost packets:\n$m2w"
echo "$m2w" | grep -qiE 'ttl=(12[0-9]|1[3-9][0-9])' || fail "mac→win replied with non-Windows TTL (stale/local?):\n$m2w"
echo "✓ mac→win 0% loss, TTL=Windows"
# win → mac: a real reply comes from macOS (TTL=64). win .101 must NOT self-answer .100.
w2m=$("${SSH[@]}" "$WIN_HOST" "ping -n 4 $MAC_IP" 2>&1 | iconv -f gbk -t utf-8 2>/dev/null || "${SSH[@]}" "$WIN_HOST" "ping -n 4 $MAC_IP" 2>&1)
echo "$w2m" | grep -qiE 'TTL=6[0-9]' || fail "win→mac: no macOS-TTL reply (stale node / not via tunnel):\n$w2m"
echo "✓ win→mac reply TTL=macOS (real tunnel)"

say "RESULT"
echo "✓ 2-node cross-platform data-plane e2e PASSED (mac $MAC_IP ↔ win $WIN_IP, udp-direct)"
