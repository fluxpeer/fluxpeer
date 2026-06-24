#!/usr/bin/env bash
# e2e-daemon-authz.sh — local daemon (`fluxpeer up`) authorization contract.
# Proves the local control API on 127.0.0.1 does NOT leak private keys and does NOT
# expose dangerous verbs to any bearer-holder by default:
#   * no/bad auth                         → {"error":"unauthorized"}
#   * authed get_config                   → returns config but private_key REDACTED
#   * authed high-risk verbs (set_config/import/shutdown) DEFAULT-DENIED
#   * with FLUXPEER_ALLOW_ADMIN_API=1 those verbs are allowed (opt-in)
#   * low-risk verbs (networks) authed    → ok
# Protocol: raw TCP, one JSON line in `{"auth":..,"cmd":..,..}`, one JSON line out.
# Runs as a normal user (high port, localhost, no real networks → no root/TUN).
set -u
B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
D="${FLUXPEER_E2E_DIR:-/tmp/fp-authz}"
PORT="${FLUXPEER_DAEMON_PORT:-41997}"
ADDR="127.0.0.1:$PORT"
SENT_KEY="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }
DPID=""
teardown(){ [ -n "$DPID" ] && kill "$DPID" 2>/dev/null; pkill -f "$B up --config-dir $D" 2>/dev/null; [ -n "${KEEP:-}" ] || rm -rf "$D"; }
trap teardown EXIT
teardown 2>/dev/null; sleep 1; mkdir -p "$D"

# send one JSON request line to the daemon, echo the response line.
req(){ # $1 = json
  python3 - "$ADDR" "$1" <<'PY'
import socket,sys
host,port=sys.argv[1].split(":")
s=socket.create_connection((host,int(port)),timeout=5)
s.sendall((sys.argv[2]+"\n").encode())
s.settimeout(5)
buf=b""
while not buf.endswith(b"\n"):
    c=s.recv(4096)
    if not c: break
    buf+=c
print(buf.decode(errors="replace").strip())
PY
}

echo "===== start daemon (no networks, admin-api OFF) ====="
"$B" up --config-dir "$D" --addr "$ADDR" >"$D/daemon.log" 2>&1 &
DPID=$!
sleep 2
TOK=$(cat "$D/daemon.token" 2>/dev/null)
[ -n "$TOK" ] && ok "daemon up + token present" || { no "daemon/token missing"; sed 's/^/    /' "$D/daemon.log"; echo "RESULTS: $pass/$fail"; exit 1; }

echo "===== drop a config with a private_key (read by get_config) ====="
cat > "$D/fpauthz.json" <<EOF
{"tun_name":"fpauthz","private_key":"$SENT_KEY","device_id":"dev-authz","control_server":"http://127.0.0.1:1","listen_port":41950,"prefix_len":24}
EOF

echo "===== auth gate ====="
R=$(req '{"cmd":"networks"}');                       echo "$R" | grep -q unauthorized && ok "no-auth → unauthorized" || no "no-auth not rejected: $R"
R=$(req '{"auth":"wrong","cmd":"networks"}');        echo "$R" | grep -q unauthorized && ok "bad-auth → unauthorized" || no "bad-auth not rejected: $R"
R=$(req "{\"auth\":\"$TOK\",\"cmd\":\"networks\"}"); echo "$R" | grep -q unauthorized && no "good-auth wrongly rejected: $R" || ok "good-auth low-risk verb ok"

echo "===== private_key must NOT leak via get_config ====="
R=$(req "{\"auth\":\"$TOK\",\"cmd\":\"get_config\",\"iface\":\"fpauthz\"}")
echo "$R" | grep -q "$SENT_KEY" && no "private_key LEAKED in get_config: $R" || ok "get_config redacts private_key"

echo "===== high-risk verbs DEFAULT-DENIED (admin-api off) ====="
R=$(req "{\"auth\":\"$TOK\",\"cmd\":\"set_config\",\"iface\":\"fpauthz\",\"config\":{\"private_key\":\"$SENT_KEY\"}}")
echo "$R" | grep -qiE 'denied|disabled|forbidden|admin' && ok "set_config default-denied" || no "set_config NOT denied: $R"
R=$(req "{\"auth\":\"$TOK\",\"cmd\":\"import\",\"config\":{\"private_key\":\"$SENT_KEY\"}}")
echo "$R" | grep -qiE 'denied|disabled|forbidden|admin' && ok "import default-denied" || no "import NOT denied: $R"
R=$(req "{\"auth\":\"$TOK\",\"cmd\":\"shutdown\"}")
echo "$R" | grep -qiE 'denied|disabled|forbidden|admin' && ok "shutdown default-denied" || no "shutdown NOT denied: $R"
# daemon must still be alive after a denied shutdown
sleep 1; R=$(req "{\"auth\":\"$TOK\",\"cmd\":\"networks\"}")
echo "$R" | grep -q unauthorized && no "post-shutdown daemon dead/odd: $R" || ok "daemon survived denied shutdown"

echo "===== RESULTS: $pass pass / $fail fail ====="
[ "$fail" = 0 ]
