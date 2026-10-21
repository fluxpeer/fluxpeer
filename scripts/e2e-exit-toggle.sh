#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Verify local provider overrides without starting a node or changing networking.
set -euo pipefail
B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
D="$(mktemp -d "${TMPDIR:-/tmp}/fp-exittoggle.XXXXXX")"
trap 'rm -rf "$D"' EXIT
cat > "$D/node.json" <<'JSON'
{"tun_name":"fp0","private_key":"00","device_id":"dev-x","control_server":"http://127.0.0.1:1","listen_port":41820,"prefix_len":24,"exit_node":false}
JSON
check(){
    python3 - "$D/node.json" "$1" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
mode = sys.argv[2]
assert cfg.get('exit_node') is (True if mode == 'on' else None), cfg
assert cfg.get('exit_veto') is (True if mode == 'veto' else None), cfg
print('PASS: set-exit ' + mode)
PY
}
for mode in on off veto follow on off; do
    "$B" node set-exit "$mode" --config-dir "$D"
    check "$mode"
done
echo 'RESULTS: 6 pass / 0 fail'
