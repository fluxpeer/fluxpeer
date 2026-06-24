#!/bin/bash
# fluxpeer single-host MULTI-PEER mesh regression — N nodes, each in its own network
# namespace, on a NAT-free bridge, all joined to ONE network so every node ends up
# with (N-1) peers. Then a full ping matrix (every node → every other) proves the
# multi-peer data plane on one Linux host:
#   - each node handshakes (N-1) peers concurrently (sessions sharded across workers)
#   - reconcile picks up later-joining peers + endpoint changes WITHOUT desyncing the
#     receiver index (the multi-peer "endpoint churn" regression: a remove+add on an
#     endpoint change tore down the live session, so the peer's DATA — still carrying
#     the old index — routed to nowhere → silent drop → relay flap; consecutive-start
#     node pairs always hit it). This test fails ~consecutive pairs if that regresses.
#   - bidirectional 0% loss across ALL N*(N-1) ordered pairs
#
# 2-node tests (regression-netns.sh) can't catch index-desync — that needs ≥3 nodes
# where a node holds ≥2 peers. Default N=5; set N=8 for a denser mesh.
#
# Requires root (netns/veth/TUN) and a built `fluxpeer` binary. Run on a Linux host:
#   N=5 FLUXPEER_BIN=./target/release/fluxpeer scripts/regression-mesh-netns.sh
set -u
N=${N:-5}
B=${FLUXPEER_BIN:-./target/release/fluxpeer}
D=${FLUXPEER_REG_DIR:-/tmp/fp-mesh-reg}
CPORT=18091            # control-server, bound on the bridge IP (reachable from every ns)
BR=10.55.0.1           # bridge / control-server host IP
SETTLE=${SETTLE:-18}   # seconds to let the full mesh handshake before the ping matrix
[ -x "$B" ] || { echo "binary not found: $B (set FLUXPEER_BIN)"; exit 1; }

cleanup() {
  sudo pkill -9 -f "fluxpeer (control|node run)" 2>/dev/null
  for i in $(seq 1 64); do sudo ip netns del mns$i 2>/dev/null; sudo ip link del vh$i 2>/dev/null; done
  sudo ip link del br-fp 2>/dev/null
}
trap cleanup EXIT
echo "===== teardown any prior run ====="
cleanup
rm -rf "$D"; mkdir -p "$D/cfg"; sleep 1

echo "===== bridge br-fp ($BR/24) + $N netns ====="
sudo ip link add br-fp type bridge
sudo ip addr add $BR/24 dev br-fp
sudo ip link set br-fp up
for i in $(seq 1 $N); do
  sudo ip netns add mns$i
  sudo ip link add vh$i type veth peer name vn$i
  sudo ip link set vh$i master br-fp; sudo ip link set vh$i up
  sudo ip link set vn$i netns mns$i
  sudo ip netns exec mns$i ip addr add 10.55.0.$((10+i))/24 dev vn$i
  sudo ip netns exec mns$i ip link set vn$i up
  sudo ip netns exec mns$i ip link set lo up
done

echo "===== control-server :$CPORT ====="
RUST_LOG=warn FLUXPEER_CONTROL_ADDR=0.0.0.0:$CPORT DATABASE_URL="sqlite://$D/c.db?mode=rwc" \
  FLUXPEER_ADMIN_PASSWORD=reg nohup "$B" control >"$D/control.log" 2>&1 &
for i in $(seq 1 20); do ss -ltn 2>/dev/null | grep -q ":$CPORT" && break; sleep 0.5; done
ss -ltn 2>/dev/null | grep -q ":$CPORT" || { echo "  FAIL: control-server up"; exit 1; }

export FLUXPEER_CONTROL_URL=http://$BR:$CPORT FLUXPEER_ADMIN_PASSWORD=reg
NET=$("$B" ctl network create mesh | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
CODE=$("$B" ctl invite create "$NET" --max-uses $((N+2)) | python3 -c 'import sys,json;print(json.load(sys.stdin)["code"])')
TOK="fp://join/$(python3 -c "import json,base64;print(base64.urlsafe_b64encode(json.dumps({'ctrl':'http://$BR:$CPORT','code':'$CODE'},separators=(',',':')).encode()).decode().rstrip('='))")"

echo "===== enroll + run $N nodes (each advertises its bridge IP) ====="
declare -a OVL
for i in $(seq 1 $N); do
  "$B" join "$TOK" --out "$D/cfg/$i.json" --no-run --name node$i >/dev/null 2>&1
  ip=10.55.0.$((10+i))
  python3 - "$D/cfg/$i.json" "$ip" <<'PY'
import sys,json
p,ip=sys.argv[1],sys.argv[2]
c=json.load(open(p)); c["advertise"]=[f"{ip}:41820"]; c["listen_port"]=41820; c["tun_name"]="fpm0"
json.dump(c,open(p,"w"))
PY
  dev=$(python3 -c "import json;print(json.load(open('$D/cfg/$i.json'))['device_id'])")
  OVL[$i]=$("$B" ctl device config "$dev" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("address_v4",""))' 2>/dev/null)
  sudo nohup ip netns exec mns$i env RUST_LOG=warn "$B" node run "$D/cfg/$i.json" >"$D/node$i.log" 2>&1 &
done
echo "  overlay IPs: ${OVL[*]:1}"
echo "  settling ${SETTLE}s for the full mesh (each node handshakes $((N-1)) peers)…"; sleep "$SETTLE"

echo "===== full-mesh ping matrix: $N nodes × $((N-1)) peers ====="
TOTAL=0; OK=0
for i in $(seq 1 $N); do
  for j in $(seq 1 $N); do
    [ "$i" -eq "$j" ] && continue
    dst=${OVL[$j]}; [ -z "$dst" ] && continue
    TOTAL=$((TOTAL+1))
    loss=$(sudo ip netns exec mns$i ping -c3 -i0.3 -W2 "$dst" 2>/dev/null | sed -n 's/.* \([0-9]*\)% packet loss.*/\1/p')
    if [ "${loss:-100}" = "0" ]; then OK=$((OK+1)); else echo "  FAIL  node$i → node$j ($dst)  loss=${loss:-?}%"; fi
  done
done
echo "============================================================"
echo "  RESULT: $OK / $TOTAL ordered node-pairs at 0% loss"
if [ "$OK" = "$TOTAL" ]; then
  echo "  PASS ✅  multi-peer mesh holds at N=$N"; exit 0
else
  echo "  FAIL ❌  $((TOTAL-OK)) pair(s) lost — multi-peer data plane regressed"; exit 1
fi
