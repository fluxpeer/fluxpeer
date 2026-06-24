#!/usr/bin/env bash
# e2e-exit-transport.sh — exit-node ↔ intranet reachability across the transport
# the CLIENT selects. Verifies that no matter which carrier a node picks (direct
# UDP, plain-TCP relay, AnyTLS/443 relay, bonded-TCP relay), a peer routing through
# an EXIT node can still reach a host on the exit's INTRANET (a LAN the peer has no
# direct route to). Linux + root only (netns/veth). Build on a Linux host; never on a node.
#
#   topology (all on one host, isolated in netns):
#
#     control + relay ── br0 10.88.0.1 ──┬── nsC  client   10.88.0.10
#                                        └── nsE  exit     10.88.0.20
#                                                  │ veth (10.99.0.1)
#                                                nsLAN intranet host 10.99.0.2
#                                                  (default route via the exit)
#
#   nsC has NO route to 10.99.0.0/24 except the one the control-server pushes
#   (exit E advertises it; admin approves) → the only way nsC reaches 10.99.0.2 is
#   through the tunnel → exit → forward. We re-run that check per transport.
set -u

B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
D="${FLUXPEER_E2E_DIR:-/tmp/fp-exit}"
CPORT="${FLUXPEER_E2E_PORT:-18092}"
RPORT_TCP=13478      # plain TCP relay + UDP STUN
RPORT_TLS=13443      # AnyTLS/443-style relay
RPORT_BOND=13479     # bonded-TCP relay
PC=41840             # client wg listen
PE=41841             # exit wg listen
BR=br0fpx
NSC=fpxC; NSE=fpxE; NSL=fpxL
CTRL="http://10.88.0.1:$CPORT"
INTRA=10.99.0.2      # intranet host behind the exit

pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }
jget(){ python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

teardown(){
  sudo pkill -x fluxpeer 2>/dev/null
  for ns in $NSC $NSE $NSL; do sudo ip netns del $ns 2>/dev/null; done
  sudo ip link del $BR 2>/dev/null
  [ -n "${KEEP:-}" ] || rm -rf "$D"
}
trap teardown EXIT
echo "===== teardown any prior run ====="; teardown 2>/dev/null; sleep 1
mkdir -p "$D/cfg"

echo "===== netns topology (br0 + client + exit + intranet) ====="
sudo ip link add $BR type bridge; sudo ip addr add 10.88.0.1/24 dev $BR; sudo ip link set $BR up
for spec in "$NSC:10.88.0.10:c" "$NSE:10.88.0.20:e"; do
  ns="${spec%%:*}"; rest="${spec#*:}"; ip="${rest%%:*}"; tag="${rest##*:}"
  sudo ip netns add $ns
  sudo ip link add v$tag type veth peer name v${tag}p
  sudo ip link set v$tag master $BR; sudo ip link set v$tag up
  sudo ip link set v${tag}p netns $ns
  sudo ip netns exec $ns ip addr add $ip/24 dev v${tag}p
  sudo ip netns exec $ns ip link set v${tag}p up
  sudo ip netns exec $ns ip link set lo up
  sudo ip netns exec $ns ip route add default via 10.88.0.1
done
# Intranet LAN: exit E ↔ host L on 10.99.0.0/24; L's default route is the exit, so
# replies to a tunnelled peer flow back through E (no LAN-side NAT needed).
sudo ip netns add $NSL
sudo ip link add vlan type veth peer name vlanp
sudo ip link set vlan netns $NSE; sudo ip link set vlanp netns $NSL
sudo ip netns exec $NSE ip addr add 10.99.0.1/24 dev vlan; sudo ip netns exec $NSE ip link set vlan up
sudo ip netns exec $NSL ip addr add 10.99.0.2/24 dev vlanp; sudo ip netns exec $NSL ip link set vlanp up
sudo ip netns exec $NSL ip link set lo up
sudo ip netns exec $NSL ip route add default via 10.99.0.1
sudo ip netns exec $NSC ping -c1 -W2 10.88.0.20 >/dev/null 2>&1 && ok "client↔exit link up" || no "client↔exit link"
# Sanity: the client must NOT reach the intranet yet (no tunnel) — else the test is meaningless.
sudo ip netns exec $NSC ping -c1 -W1 $INTRA >/dev/null 2>&1 && no "intranet reachable WITHOUT tunnel (bad isolation)" || ok "intranet isolated pre-tunnel"

echo "===== control-server + multi-transport relay ====="
DATABASE_URL="sqlite://$D/db.sqlite?mode=rwc" FLUXPEER_CONTROL_ADDR=0.0.0.0:$CPORT FLUXPEER_ADMIN_PASSWORD=reg \
  nohup $B control >"$D/control.log" 2>&1 & sleep 2
# ONE relay process, three carriers + STUN, all on the bridge IP.
FLUXPEER_RELAY_ADDR=0.0.0.0:$RPORT_TCP FLUXPEER_RELAY_ANYTLS_ADDR=0.0.0.0:$RPORT_TLS \
  FLUXPEER_RELAY_BOND_ADDR=0.0.0.0:$RPORT_BOND FLUXPEER_RELAY_NODE_ID=fluxpeer-relay \
  nohup $B relay >"$D/relay.log" 2>&1 & sleep 2
curl -s $CTRL/health >/dev/null && ok "control-server up" || no "control-server down"
# ctl reads these for the admin bearer + base URL (admin routes are bearer-gated).
export FLUXPEER_CONTROL_URL=$CTRL FLUXPEER_ADMIN_PASSWORD=reg

echo "===== network + enroll exit + client ====="
$B ctl --server $CTRL network create exitnet >/dev/null 2>&1
NID=$($B ctl --server $CTRL network list 2>/dev/null | grep -oE 'net-[0-9]+' | head -1)
mktok(){ local c=$($B ctl --server $CTRL invite create "$NID" 2>/dev/null | grep -oE '[0-9a-f]{32}' | head -1)
  python3 -c "import json,base64;print('fp://join/'+base64.urlsafe_b64encode(json.dumps({'ctrl':'$CTRL','code':'$c'}).encode()).decode().rstrip('='))"; }
$B join "$(mktok)" --out "$D/cfg/E.json" --no-run --name exit  2>&1 | grep -q enrolled && ok "exit enrolled"   || no "exit enroll"
$B join "$(mktok)" --out "$D/cfg/C.json" --no-run --name client 2>&1 | grep -q enrolled && ok "client enrolled" || no "client enroll"
IDE=$(python3 -c "import json;print(json.load(open('$D/cfg/E.json'))['device_id'])")
IDC=$(python3 -c "import json;print(json.load(open('$D/cfg/C.json'))['device_id'])")
TOKE=$(python3 -c "import json;print(json.load(open('$D/cfg/E.json')).get('auth_token',''))")
TOKC=$(python3 -c "import json;print(json.load(open('$D/cfg/C.json')).get('auth_token',''))")

echo "===== exit advertises the intranet route; admin approves ====="
RID=$($B ctl --server $CTRL route add "$IDE" 10.99.0.0/24 2>/dev/null | jget id)
[ -n "$RID" ] && $B ctl --server $CTRL route approve "$RID" >/dev/null 2>&1 && ok "intranet route approved" || no "route approve (id=$RID)"
# Reachable mesh endpoints (so the DIRECT transport can punch over the bridge).
curl -s -X POST $CTRL/api/v1/devices/$IDC/endpoints -H 'content-type: application/json' -H "Authorization: Bearer $TOKC" -d "{\"endpoints\":[\"10.88.0.10:$PC\"]}" >/dev/null
curl -s -X POST $CTRL/api/v1/devices/$IDE/endpoints -H 'content-type: application/json' -H "Authorization: Bearer $TOKE" -d "{\"endpoints\":[\"10.88.0.20:$PE\"]}" >/dev/null

# Pristine post-enroll configs: each transport case is rebuilt from these so a knob
# set in one case (e.g. relay_anytls) can't bleed into the next.
cp "$D/cfg/C.json" "$D/cfg/C.base.json"; cp "$D/cfg/E.json" "$D/cfg/E.base.json"

# Rebuild a node config from its base: $1=base-tag(C|E) $2=tun $3=port $4=extra-json
patch(){ python3 -c "import json,sys
b='$D/cfg/$1.base.json';p='$D/cfg/$1.json';c=json.load(open(b));c['tun_name']='$2';c['listen_port']=$3
c.update(json.loads('''$4'''));json.dump(c,open(p,'w'))"; }

# Transport matrix the CLIENT selects. Each entry patches BOTH ends to that carrier
# (the C↔E mesh hop must agree); the exit↔intranet forwarding is identical underneath.
#   name            | client+exit extra config
run_case(){
  local name="$1" extra="$2"
  echo "----- transport: $name -----"
  patch E fpxe $PE "{\"exit_node\":true${extra:+,$extra}}"
  patch C fpxc $PC "{${extra}}"
  sudo RUST_LOG="${RUST_LOG:-warn}" nohup ip netns exec $NSE $B node run "$D/cfg/E.json" >"$D/E.$name.log" 2>&1 &
  sudo RUST_LOG="${RUST_LOG:-warn}" nohup ip netns exec $NSC $B node run "$D/cfg/C.json" >"$D/C.$name.log" 2>&1 &
  # Relay carriers (esp. the bonded N-way join) need longer than direct to settle.
  local settle="${SETTLE:-12}"; case "$name" in relay-*) settle="${SETTLE_RELAY:-20}";; esac
  echo "  waiting ${settle}s for handshake + route install…"; sleep "$settle"
  # The actual check: client → intranet host, only possible via tunnel→exit→forward.
  local PR; PR=$(sudo ip netns exec $NSC ping -c5 -i0.3 -W2 $INTRA 2>&1)
  local LOSS; LOSS=$(echo "$PR" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
  local TP; TP=$(sudo ip netns exec $NSC $B show 2>/dev/null | grep -oE '\((udp|tcp)-direct\)|relay' | head -1)
  if [ "${LOSS:-100}" = "0" ]; then ok "[$name] client → intranet $INTRA via exit (0% loss; carrier=${TP:-?})"
  else no "[$name] client → intranet $INTRA (loss=${LOSS:-?}%, carrier=${TP:-?})"; echo "$PR" | tail -2 | sed 's/^/      /'; fi
  sudo pkill -f "node run" 2>/dev/null; sleep 2
}

echo "===== exit↔intranet across client-selected transports ====="
run_case direct       ''
run_case relay-tcp    "\"force_relay\":true,\"relay\":\"10.88.0.1:$RPORT_TCP\""
run_case relay-anytls "\"force_relay\":true,\"relay\":\"10.88.0.1:$RPORT_TLS\",\"relay_anytls\":true,\"relay_node_id\":\"fluxpeer-relay\""
run_case relay-bond   "\"force_relay\":true,\"relay\":\"10.88.0.1:$RPORT_BOND\",\"relay_bond\":true"

echo "===== RESULTS: $pass pass / $fail fail ====="
[ "$fail" = "0" ]
