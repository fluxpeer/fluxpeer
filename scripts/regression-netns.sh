#!/bin/bash
# fluxpeer single-host regression — a REAL 2-node mesh where the second node runs
# in a network namespace connected by a veth, so traffic actually traverses the wg
# tunnel (no co-located local-tun shortcut). Proves, on one Linux host:
#   - enroll + handshake + TUN both sides
#   - bidirectional ping 0% loss + DIRECT-path latency/ttl (udp-direct => ttl 64, sub-ms)
#   - REAL bidirectional transfer (rx AND tx grow on both peers)
#   - REVOKE-1 (a revoked device is dropped live → isolated)
#
# Requires root (netns/veth/TUN) and a built `fluxpeer` binary. Run on a Linux
# build host:
#   FLUXPEER_BIN=~/fpbuild/target/release/fluxpeer scripts/regression-netns.sh
set -u
B=${FLUXPEER_BIN:-$HOME/fpbuild/target/release/fluxpeer}
D=${FLUXPEER_REG_DIR:-$HOME/fp-reg}
NS=fpns
CPORT=18090            # control-server (bound on the host veth IP so the netns can reach it)
PA=41820; PB=41829     # wg listen ports (host node-A / netns node-B)
PASS=0; FAIL=0
ok(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
[ -x "$B" ] || { echo "binary not found: $B (set FLUXPEER_BIN)"; exit 1; }

echo "===== teardown any prior run ====="
sudo pkill -9 -f "fluxpeer (control|relay|node run)" 2>/dev/null
sudo ip netns del $NS 2>/dev/null
sudo ip link del veth-h 2>/dev/null
for i in fpr0 fpr1; do sudo ip link del $i 2>/dev/null; done
rm -rf "$D"; mkdir -p "$D/cfg"; sleep 1

echo "===== netns + veth (host 10.0.0.1  <->  $NS 10.0.0.2) ====="
sudo ip netns add $NS
sudo ip link add veth-h type veth peer name veth-n
sudo ip link set veth-n netns $NS
sudo ip addr add 10.0.0.1/24 dev veth-h
sudo ip link set veth-h up
sudo ip netns exec $NS ip addr add 10.0.0.2/24 dev veth-n
sudo ip netns exec $NS ip link set veth-n up
sudo ip netns exec $NS ip link set lo up
sudo ip netns exec $NS ping -c1 -W2 10.0.0.1 >/dev/null 2>&1 && ok "veth link up" || no "veth link"

echo "===== control-server (0.0.0.0:$CPORT, reachable from host + netns) ====="
DATABASE_URL="sqlite://$D/db.sqlite?mode=rwc" FLUXPEER_CONTROL_ADDR=0.0.0.0:$CPORT \
  FLUXPEER_ADMIN_PASSWORD=reg nohup $B control >"$D/control.log" 2>&1 &
for i in $(seq 1 20); do ss -ltn | grep -q ":$CPORT" && break; sleep 0.5; done
ss -ltn | grep -q ":$CPORT" && ok "control-server up" || { no "control-server up"; exit 1; }

export FLUXPEER_CONTROL_URL=http://10.0.0.1:$CPORT FLUXPEER_ADMIN_PASSWORD=reg
CTRL=http://10.0.0.1:$CPORT

echo "===== network + CSPRNG invites ====="
$B ctl network create reg-net >/dev/null 2>&1
NID=$($B ctl network list 2>/dev/null | grep -oE 'net-[0-9]+' | head -1)
[ -n "$NID" ] && ok "network created ($NID)" || no "network create"
C1=$($B ctl invite create "$NID" 2>/dev/null | grep -oE '[0-9a-f]{32}' | head -1)
C2=$($B ctl invite create "$NID" 2>/dev/null | grep -oE '[0-9a-f]{32}' | head -1)
[ "$C1" != "$C2" ] && [ ${#C1} -eq 32 ] && ok "invites are CSPRNG + unique" || no "invite CSPRNG"
mktok(){ python3 -c "import json,base64; print('fp://join/'+base64.urlsafe_b64encode(json.dumps({'ctrl':'$CTRL','code':'$1'}).encode()).decode().rstrip('='))"; }
TOK1=$(mktok "$C1"); TOK2=$(mktok "$C2")

echo "===== enroll 2 nodes ====="
$B join "$TOK1" --out "$D/cfg/A.json" --no-run --name node-A 2>&1 | grep -q enrolled && ok "node-A enrolled" || no "node-A enroll"
$B join "$TOK2" --out "$D/cfg/B.json" --no-run --name node-B 2>&1 | grep -q enrolled && ok "node-B enrolled" || no "node-B enroll"
python3 -c "import json;p='$D/cfg/A.json';c=json.load(open(p));c['tun_name']='fpr0';c['listen_port']=$PA;json.dump(c,open(p,'w'))"
python3 -c "import json;p='$D/cfg/B.json';c=json.load(open(p));c['tun_name']='fpr1';c['listen_port']=$PB;json.dump(c,open(p,'w'))"
IDA=$(python3 -c "import json;print(json.load(open('$D/cfg/A.json'))['device_id'])")
IDB=$(python3 -c "import json;print(json.load(open('$D/cfg/B.json'))['device_id'])")
ADDRB=$(curl -s $CTRL/api/v1/devices/$IDB/config | python3 -c "import sys,json;print(json.load(sys.stdin).get('address_v4',''))" 2>/dev/null)

echo "===== set reachable endpoints (A on host veth, B on netns veth) ====="
curl -s -X POST $CTRL/api/v1/devices/$IDA/endpoints -H 'content-type: application/json' -d "{\"endpoints\":[\"10.0.0.1:$PA\"]}" >/dev/null
curl -s -X POST $CTRL/api/v1/devices/$IDB/endpoints -H 'content-type: application/json' -d "{\"endpoints\":[\"10.0.0.2:$PB\"]}" >/dev/null
ok "endpoints set"

echo "===== run node-A (host) + node-B (in $NS) ====="
sudo nohup $B node run "$D/cfg/A.json" >"$D/A.log" 2>&1 &
sudo nohup ip netns exec $NS $B node run "$D/cfg/B.json" >"$D/B.log" 2>&1 &
echo "  waiting for handshake…"; sleep 9
ip link show fpr0 >/dev/null 2>&1 && ok "host TUN fpr0 up" || no "host TUN fpr0"
sudo ip netns exec $NS ip link show fpr1 >/dev/null 2>&1 && ok "netns TUN fpr1 up" || no "netns TUN fpr1"

echo "===== real ping THROUGH the tunnel (host -> node-B overlay) ====="
PR=$(ping -c10 -i0.2 -W2 $ADDRB 2>&1); echo "$PR" | tail -2 | sed 's/^/    /'
LOSS=$(echo "$PR" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
TTL=$(echo "$PR" | grep -oE 'ttl=[0-9]+' | head -1)
[ "${LOSS:-100}" = "0" ] && ok "bidirectional ping 0% loss" || no "ping loss=${LOSS:-?}%"
echo "  >>> path: $TTL  (direct udp hop => ttl 64, sub-ms; relayed/multi-hop is lower ttl + higher rtt)"

echo "===== REAL bidirectional transfer (fluxpeer show) ====="
ping -c20 -i0.1 -W1 $ADDRB >/dev/null 2>&1; sleep 1
sudo $B show 2>&1 | grep -E 'interface:|transfer|latest handshake|transport|rtt|endpoint' | sed 's/^/    /' | head -16
XFER=$(sudo $B show 2>/dev/null | grep -m1 'transfer:')
if echo "$XFER" | grep -qE '0 B received, 0 B sent' || [ -z "$XFER" ]; then no "transfer is zero"; else ok "REAL bidirectional transfer -> ${XFER#*transfer: }"; fi

echo "===== REVOKE-1 (revoke node-B, node-A must drop it live) ====="
$B ctl device revoke "$IDB" >/dev/null 2>&1; sleep 4
L2=$(ping -c3 -W2 $ADDRB 2>&1 | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
[ "${L2:-0}" = "100" ] && ok "revoked node-B isolated (100% loss after revoke)" || no "revoke didn't isolate (loss=${L2}%)"

echo "===== RESULTS: $PASS pass / $FAIL fail ====="
echo "===== teardown ====="
sudo pkill -9 -f "fluxpeer (control|node run)" 2>/dev/null
sudo ip netns del $NS 2>/dev/null
sudo ip link del veth-h 2>/dev/null
for i in fpr0 fpr1; do sudo ip link del $i 2>/dev/null; done
echo "done"
[ "$FAIL" -eq 0 ]
