#!/usr/bin/env bash
# Real-WAN mesh e2e (testing layer 3).
#
# Uses a PUBLIC control+relay and two nodes behind DIFFERENT NATs (node-a behind a
# single NAT, node-b behind a double NAT), then verifies they reach each other's
# overlay over the real internet (udp-direct hole-punch, or relay fallback via the
# public relay). This exercises NAT traversal + relay, which netns/LAN tests can't.
#
# Supply your own infra (no defaults are baked in) via flags or env:
#   scripts/e2e-wan.sh --ctl http://HOST:8090 --admin PW --relay HOST:3478 \
#                      --node-a <ssh-host> --node-b <ssh-host> [--keep]
# env equivalents: FLUXPEER_E2E_CTL / FLUXPEER_ADMIN_PASSWORD / FLUXPEER_E2E_RELAY /
#                  FLUXPEER_E2E_NODE_A / FLUXPEER_E2E_NODE_B
#
# Bakes in the bring-up gotchas (see also e2e-2node.sh):
#  - kill stale fp-node on both nodes first.
#  - configs get the public relay + STUN (relay doubles as STUN) so NATed nodes
#    learn their reflexive address and can fall back to relay.
#  - run nodes over HELD-OPEN ssh (so they live); cleanup tears down + revokes.
#  - ssh/scp with -o ProxyCommand=none.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# No defaults are baked in — provide your own control/relay/hosts (see header).
CTL="${FLUXPEER_E2E_CTL:-}"
ADMIN="${FLUXPEER_ADMIN_PASSWORD:-}"
RELAY="${FLUXPEER_E2E_RELAY:-}"
NODE_A="${FLUXPEER_E2E_NODE_A:-}"
NODE_B="${FLUXPEER_E2E_NODE_B:-}"
KEEP=0
while [ $# -gt 0 ]; do case "$1" in
  --ctl) CTL="$2"; shift 2 ;;
  --admin) ADMIN="$2"; shift 2 ;;
  --relay) RELAY="$2"; shift 2 ;;
  --node-a) NODE_A="$2"; shift 2 ;;
  --node-b) NODE_B="$2"; shift 2 ;;
  --keep) KEEP=1; shift ;;
  *) echo "unknown arg: $1"; exit 2 ;;
esac; done

# Require the infra params — nothing is hardcoded.
missing=""
[ -n "$CTL" ]    || missing="$missing --ctl"
[ -n "$ADMIN" ]  || missing="$missing --admin"
[ -n "$RELAY" ]  || missing="$missing --relay"
[ -n "$NODE_A" ] || missing="$missing --node-a"
[ -n "$NODE_B" ] || missing="$missing --node-b"
if [ -n "$missing" ]; then
  echo "missing required:$missing (pass as flags or env — see header)" >&2
  exit 2
fi

SSH=(ssh -o ProxyCommand=none -o ProxyJump=none -o ConnectTimeout=15)
SCP=(scp -o ProxyCommand=none -o ProxyJump=none -o ConnectTimeout=15)
FLUX=target/debug/fluxpeer        # local CLI/ctl/join (talks to the public control)
NODE_A_BIN=fpbuild/target/x86_64-unknown-linux-musl/release/fluxpeer  # relative to node-a home (scp expands it remotely)
REMOTE=fluxpeer-wan               # binary path on each node (home dir)
TMP=$(mktemp -d /tmp/fpwan.XXXX)
A_SSH=""; B_SSH=""; NET=""

say() { echo; echo "━━━ $* ━━━"; }
fail() { echo "✗ FAIL: $*"; cleanup; exit 1; }

cleanup() {
  [ "$KEEP" = 1 ] && { echo "(--keep: leaving nodes running; network $NET not revoked)"; return; }
  say "cleanup"
  [ -n "$A_SSH" ] && kill "$A_SSH" 2>/dev/null
  [ -n "$B_SSH" ] && kill "$B_SSH" 2>/dev/null
  for n in "$NODE_A" "$NODE_B"; do "${SSH[@]}" "$n" 'sudo pkill -f "fluxpeer-wan node run" 2>/dev/null' 2>/dev/null; done
  rm -rf "$TMP"
}
trap cleanup EXIT

export FLUXPEER_ADMIN_PASSWORD=$ADMIN
echo "control: $CTL   relay: $RELAY   nodes: $NODE_A(NAT) ↔ $NODE_B(2xNAT)"

say "local CLI build + control reachable"
cargo build -q -p fluxpeer || fail "local build"
curl -s --max-time 10 "$CTL/api/v1/health" | grep -q ok || fail "public control $CTL not reachable/healthy"
echo "✓ control healthy"

say "kill stale nodes (so the staged binary isn't busy)"
for n in "$NODE_A" "$NODE_B"; do "${SSH[@]}" "$n" 'sudo pkill -f "fluxpeer-wan node run" 2>/dev/null; true' 2>/dev/null; done
sleep 1

say "stage the linux binary on both nodes (node-a has it; copy via here to node-b)"
"${SCP[@]}" "$NODE_A:$NODE_A_BIN" "$TMP/fp-linux" >/dev/null 2>&1 || fail "fetch binary from $NODE_A"
for n in "$NODE_A" "$NODE_B"; do "${SCP[@]}" "$TMP/fp-linux" "$n:$REMOTE" >/dev/null 2>&1 || fail "stage binary to $n"; "${SSH[@]}" "$n" "chmod +x $REMOTE" 2>/dev/null; done
echo "✓ binary staged"

say "create network + enroll 2 nodes via the public control"
NET=$("$FLUX" ctl --server "$CTL" network create wan | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])') || fail "create network"
mktoken() { python3 -c "import base64,json;print('fp://join/'+base64.urlsafe_b64encode(json.dumps({'ctrl':'$CTL','code':'$1'}).encode()).decode().rstrip('='))"; }
IA=$("$FLUX" ctl --server "$CTL" invite create "$NET" | python3 -c 'import sys,json;print(json.load(sys.stdin)["code"])')
IB=$("$FLUX" ctl --server "$CTL" invite create "$NET" | python3 -c 'import sys,json;print(json.load(sys.stdin)["code"])')
"$FLUX" join "$(mktoken "$IA")" --no-run --out "$TMP/a.json" --name wan-a >/dev/null 2>&1 || fail "enroll a"
"$FLUX" join "$(mktoken "$IB")" --no-run --out "$TMP/b.json" --name wan-b >/dev/null 2>&1 || fail "enroll b"
# Give both configs the public relay + STUN (relay doubles as STUN) so NATed nodes
# learn their reflexive address and can relay-fall-back if hole-punch fails.
for f in a b; do python3 -c "import json;c=json.load(open('$TMP/$f.json'));c['stun_server']='$RELAY';c['relay']='$RELAY';json.dump(c,open('$TMP/$f.json','w'))"; done
# Multi-iface nodes (LAN + VPN + docker) otherwise advertise an addr the peer can't
# reach (handshake completes via STUN-reflexive but data is one-way — same as the
# layer-2 finding). Pin each node's advertised endpoint to its primary LAN IP.
A_LAN=$("${SSH[@]}" "$NODE_A" "hostname -I" 2>/dev/null | tr ' ' '\n' | grep -E '^(192\.168|10\.[0-9])' | head -1)
B_LAN=$("${SSH[@]}" "$NODE_B" "hostname -I" 2>/dev/null | tr ' ' '\n' | grep -E '^(192\.168|10\.[0-9])' | head -1)
[ -n "$A_LAN" ] && python3 -c "import json;c=json.load(open('$TMP/a.json'));c['advertise']=['$A_LAN:'+str(c['listen_port'])];json.dump(c,open('$TMP/a.json','w'))"
[ -n "$B_LAN" ] && python3 -c "import json;c=json.load(open('$TMP/b.json'));c['advertise']=['$B_LAN:'+str(c['listen_port'])];json.dump(c,open('$TMP/b.json','w'))"
echo "  advertise: $NODE_A=$A_LAN  $NODE_B=$B_LAN"
A_IP=$(python3 -c "import sys,json;[print(d['address_v4']) for d in json.load(sys.stdin) if d['name']=='wan-a']" < <("$FLUX" ctl --server "$CTL" device list "$NET"))
B_IP=$(python3 -c "import sys,json;[print(d['address_v4']) for d in json.load(sys.stdin) if d['name']=='wan-b']" < <("$FLUX" ctl --server "$CTL" device list "$NET"))
echo "✓ overlay: $NODE_A=$A_IP  $NODE_B=$B_IP"

say "deploy configs + start nodes (held-open ssh)"
"${SCP[@]}" "$TMP/a.json" "$NODE_A:wan.json" >/dev/null 2>&1 || fail "scp config a"
"${SCP[@]}" "$TMP/b.json" "$NODE_B:wan.json" >/dev/null 2>&1 || fail "scp config b"
"${SSH[@]}" "$NODE_A" "sudo RUST_LOG=info ./$REMOTE node run wan.json" >"$TMP/a.log" 2>&1 & A_SSH=$!
"${SSH[@]}" "$NODE_B" "sudo RUST_LOG=info ./$REMOTE node run wan.json" >"$TMP/b.log" 2>&1 & B_SSH=$!

say "wait for cross-NAT reachability (node-a → node-b overlay, up to ~60s)"
ok=0
for _ in $(seq 1 30); do
  sleep 2
  if "${SSH[@]}" "$NODE_A" "ping -c 1 -W 2 $B_IP" >/dev/null 2>&1; then ok=1; break; fi
done
[ "$ok" = 1 ] || { echo "--- node-a log ---"; tail -8 "$TMP/a.log"; echo "--- node-b log ---"; tail -8 "$TMP/b.log"; fail "node-a never reached node-b overlay ($B_IP) over WAN"; }

say "verify bidirectional + report transport path"
# WAN NAT traversal can drop the first packet(s) while the direct path settles, so
# accept <50% loss as "reachable" rather than demanding a perfectly clean run.
chk() { # $1=from-host  $2=dst-ip  $3=label
  local out loss
  out=$("${SSH[@]}" "$1" "ping -c 6 $2" 2>&1)
  loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
  { [ -n "$loss" ] && [ "$loss" -lt 50 ]; } || fail "$3 unreachable (${loss:-100}% loss over WAN)"
  echo "✓ $3 reachable (${loss}% loss)"
}
chk "$NODE_A" "$B_IP" "$NODE_A -> $NODE_B"
chk "$NODE_B" "$A_IP" "$NODE_B -> $NODE_A"
echo "--- transport (node-a view) ---"
"${SSH[@]}" "$NODE_A" "sudo ./$REMOTE show 2>/dev/null | grep -iE 'endpoint|transport|rtt|transfer'" 2>/dev/null | head

say "RESULT"
echo "✓ real-WAN cross-NAT mesh e2e PASSED ($NODE_A $A_IP ↔ $NODE_B $B_IP via $CTL)"
