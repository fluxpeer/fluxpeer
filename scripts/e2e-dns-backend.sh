#!/usr/bin/env bash
# DNS backend — `fluxpeer dns-selftest set|clear|detect`. On OpenWrt (uci +
# /etc/config/dhcp) DNS is applied via dnsmasq UCI (noresolv + upstream server) so a
# full-tunnel router resolves through the mesh; elsewhere resolvectl/resolv.conf. Black-
# box via the seam; run in the OpenWrt container (has uci).
set -u
B="${FLUXPEER_BIN:-/usr/sbin/fluxpeer}"
DNS="${TEST_DNS:-100.72.0.53}"
pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }

det=$("$B" dns-selftest detect 2>&1)
echo "detect: $det"
if command -v uci >/dev/null 2>&1 && [ -f /etc/config/dhcp ]; then
  echo "$det" | grep -qiE 'uci|dnsmasq|openwrt' && ok "detect = openwrt/uci backend" || no "detect not uci (got: $det)"
  "$B" dns-selftest set "$DNS" >/dev/null 2>&1
  nores=$(uci -q get dhcp.@dnsmasq[0].noresolv 2>/dev/null)
  srv=$(uci -q get dhcp.@dnsmasq[0].server 2>/dev/null)
  [ "$nores" = 1 ] && ok "set -> noresolv=1" || no "set noresolv not 1 (got: $nores)"
  echo "$srv" | grep -q "$DNS" && ok "set -> dnsmasq upstream has $DNS" || no "set server missing $DNS (got: $srv)"
  "$B" dns-selftest clear >/dev/null 2>&1
  srv2=$(uci -q get dhcp.@dnsmasq[0].server 2>/dev/null)
  echo "$srv2" | grep -q "$DNS" && no "clear did not remove $DNS (got: $srv2)" || ok "clear -> upstream $DNS removed"
else
  echo "  (non-OpenWrt host: detect=$det; uci/dnsmasq path not exercised)"
  [ -n "$det" ] && ok "detect returned a backend" || no "detect empty"
fi
echo "===== RESULTS: $pass pass / $fail fail ====="
[ "$fail" = 0 ]
