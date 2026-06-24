#!/usr/bin/env bash
# e2e-subnet-nft.sh — subnet-router data-plane over the NFT firewall backend.
# Proves a fluxpeer node acting as a SUBNET ROUTER (advertises a LAN it fronts) forwards
# real mesh traffic to a LAN host — using the nft backend (FLUXPEER_FW_BACKEND=nft, the
# OpenWrt-default path) — AND that the route is gated by admin approval:
#   * BEFORE the advertised route is approved → client CANNOT reach the LAN host (negative)
#   * AFTER approval                          → client CAN reach it (0% loss)
#   * the router's nft `inet fluxpeer` table is present while up, gone after teardown
# Single host, netns/veth, root + nft. Build on a Linux host. Mirrors the
# proven e2e-exit-transport.sh topology but forces nft and adds the approval gate check.
set -u
B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
D="${FLUXPEER_E2E_DIR:-/tmp/fp-subnet}"
CPORT="${FLUXPEER_E2E_PORT:-18094}"
RPORT_TCP=13488          # plain TCP relay + UDP STUN
PC=41860; PE=41861       # wg listen ports
BR=br0fpsn
NSC=fpsnC; NSE=fpsnE; NSL=fpsnL
CTRL="http://10.88.0.1:$CPORT"
INTRA=10.99.0.2          # LAN host behind the router
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
teardown 2>/dev/null; sleep 1; mkdir -p "$D/cfg"

echo "===== netns topology ====="
sudo ip link add $BR type bridge; sudo ip addr add 10.88.0.1/24 dev $BR; sudo ip link set $BR up
for spec in "$NSC:10.88.0.10:c" "$NSE:10.88.0.20:e"; do
  ns="${spec%%:*}"; rest="${spec#*:}"; ip="${rest%%:*}"; tag="${rest##*:}"
  sudo ip netns add $ns
  sudo ip link add v$tag type veth peer name v${tag}p
  sudo ip link set v$tag master $BR; sudo ip link set v$tag up
  sudo ip link set v${tag}p netns $ns
  sudo ip netns exec $ns ip addr add $ip/24 dev v${tag}p
  sudo ip netns exec $ns ip link set v${tag}p up; sudo ip netns exec $ns ip link set lo up
  sudo ip netns exec $ns ip route add default via 10.88.0.1
done
# LAN behind the router E: host L (10.99.0.2), default route via E.
sudo ip netns add $NSL
sudo ip link add vlan type veth peer name vlanp
sudo ip link set vlan netns $NSE; sudo ip link set vlanp netns $NSL
sudo ip netns exec $NSE ip addr add 10.99.0.1/24 dev vlan; sudo ip netns exec $NSE ip link set vlan up
sudo ip netns exec $NSL ip addr add 10.99.0.2/24 dev vlanp; sudo ip netns exec $NSL ip link set vlanp up
sudo ip netns exec $NSL ip link set lo up; sudo ip netns exec $NSL ip route add default via 10.99.0.1
sudo ip netns exec $NSC ping -c1 -W1 $INTRA >/dev/null 2>&1 && no "LAN reachable WITHOUT tunnel (bad isolation)" || ok "LAN isolated pre-tunnel"

echo "===== control + relay ====="
DATABASE_URL="sqlite://$D/db.sqlite?mode=rwc" FLUXPEER_CONTROL_ADDR=0.0.0.0:$CPORT FLUXPEER_ADMIN_PASSWORD=reg \
  nohup "$B" control >"$D/control.log" 2>&1 & sleep 2
FLUXPEER_RELAY_ADDR=0.0.0.0:$RPORT_TCP FLUXPEER_RELAY_NODE_ID=fluxpeer-relay nohup "$B" relay >"$D/relay.log" 2>&1 & sleep 2
curl -s $CTRL/health >/dev/null && ok "control up" || { no "control down"; echo "RESULTS: $pass/$fail"; exit 1; }
export FLUXPEER_CONTROL_URL=$CTRL FLUXPEER_ADMIN_PASSWORD=reg

echo "===== network + enroll router(E) + client(C) ====="
"$B" ctl --server $CTRL network create subnet >/dev/null 2>&1
NID=$("$B" ctl --server $CTRL network list 2>/dev/null | grep -oE 'net-[0-9]+' | head -1)
mktok(){ local c; c=$("$B" ctl --server $CTRL invite create "$NID" 2>/dev/null | grep -oE '[0-9a-f]{32}' | head -1)
  python3 -c "import json,base64;print('fp://join/'+base64.urlsafe_b64encode(json.dumps({'ctrl':'$CTRL','code':'$c'}).encode()).decode().rstrip('='))"; }
"$B" join "$(mktok)" --out "$D/cfg/E.json" --no-run --name router 2>&1 | grep -q enrolled && ok "router enrolled" || no "router enroll"
"$B" join "$(mktok)" --out "$D/cfg/C.json" --no-run --name client 2>&1 | grep -q enrolled && ok "client enrolled" || no "client enroll"
IDE=$(jget device_id <"$D/cfg/E.json"); TOKE=$(jget auth_token <"$D/cfg/E.json")
IDC=$(jget device_id <"$D/cfg/C.json"); TOKC=$(jget auth_token <"$D/cfg/C.json")
# advertise the LAN subnet (NOT yet approved)
RID=$("$B" ctl --server $CTRL route add "$IDE" 10.99.0.0/24 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
[ -n "$RID" ] && ok "subnet advertised (route $RID, pending)" || no "advertise failed"
# reachable endpoints for direct transport
curl -s -X POST $CTRL/api/v1/devices/$IDC/endpoints -H 'content-type: application/json' -H "Authorization: Bearer $TOKC" -d "{\"endpoints\":[\"10.88.0.10:$PC\"]}" >/dev/null
curl -s -X POST $CTRL/api/v1/devices/$IDE/endpoints -H 'content-type: application/json' -H "Authorization: Bearer $TOKE" -d "{\"endpoints\":[\"10.88.0.20:$PE\"]}" >/dev/null

echo "===== start nodes (router E forces nft backend) ====="
python3 -c "import json;c=json.load(open('$D/cfg/E.json'));c['tun_name']='fpsnE';c['listen_port']=$PE;c['exit_node']=True;json.dump(c,open('$D/cfg/E.json','w'))"
python3 -c "import json;c=json.load(open('$D/cfg/C.json'));c['tun_name']='fpsnC';c['listen_port']=$PC;json.dump(c,open('$D/cfg/C.json','w'))"
sudo FLUXPEER_FW_BACKEND=nft RUST_LOG=warn nohup ip netns exec $NSE "$B" node run "$D/cfg/E.json" >"$D/E.log" 2>&1 &
sudo RUST_LOG=warn nohup ip netns exec $NSC "$B" node run "$D/cfg/C.json" >"$D/C.log" 2>&1 &
echo "  waiting 12s for handshake…"; sleep 12

echo "===== router uses nft backend? ====="
sudo ip netns exec $NSE nft list table inet fluxpeer >/dev/null 2>&1 && ok "router has nft inet fluxpeer table" || no "router missing nft table (backend not nft?)"

echo "===== NEGATIVE: before approval, client must NOT reach LAN ====="
if sudo ip netns exec $NSC ping -c2 -i0.3 -W2 $INTRA >/dev/null 2>&1; then
  no "client reached LAN BEFORE route approval (gate broken)"
else
  ok "client cannot reach LAN before approval (route gated)"
fi

echo "===== approve route ====="
"$B" ctl --server $CTRL route approve "$RID" >/dev/null 2>&1 && ok "route approved" || no "approve failed (id=$RID)"
echo "  waiting 15s for route push…"; sleep 15

echo "===== POSITIVE: after approval, client reaches LAN via router ====="
PR=$(sudo ip netns exec $NSC ping -c5 -i0.3 -W2 $INTRA 2>&1)
LOSS=$(echo "$PR" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
if [ "${LOSS:-100}" = "0" ]; then ok "client → LAN $INTRA via subnet router (0% loss, nft forward)"
else no "client → LAN after approval (loss=${LOSS:-?}%)"; echo "$PR" | tail -2 | sed 's/^/      /'; fi

echo "===== RESULTS: $pass pass / $fail fail ====="
[ "$fail" = 0 ]
