#!/usr/bin/env bash
# exit toggle wiring — `fluxpeer node set-exit on|off` patches a node config's
# exit_node so the LuCI/rpcd/UCI exit toggle actually takes effect. Pure config edit
# (no mesh needed; exit data-plane forwarding already proven by e2e-subnet-nft.sh). Runs anywhere.
set -u
B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
D="${FLUXPEER_E2E_DIR:-/tmp/fp-exittoggle}"
pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }
rm -rf "$D"; mkdir -p "$D"
cat > "$D/node.json" <<JSON
{"tun_name":"fp0","private_key":"00","device_id":"dev-x","control_server":"http://127.0.0.1:1","listen_port":41820,"prefix_len":24,"exit_node":false}
JSON
exitval(){ grep -oE '"exit_node"[[:space:]]*:[[:space:]]*(true|false)' "$D/node.json" | grep -oE 'true|false' | head -1; }

"$B" node set-exit on --config-dir "$D" >/dev/null 2>&1
[ "$(exitval)" = true ] && ok "set-exit on -> exit_node=true" || no "set-exit on did not set true (got: $(exitval))"
"$B" node set-exit off --config-dir "$D" >/dev/null 2>&1
[ "$(exitval)" = false ] && ok "set-exit off -> exit_node=false" || no "set-exit off did not set false (got: $(exitval))"

echo "===== RESULTS: $pass pass / $fail fail ====="
rm -rf "$D"
[ "$fail" = 0 ]
