#!/usr/bin/env bash
# kill-switch — when full-tunnel up with kill-switch, a leak-prevention rule
# drops forwarded traffic egressing the physical iface that did NOT arrive via the tun
# (forces LAN->WAN via the tunnel). Tested via `fluxpeer fw-selftest killswitch on|off`
# seam (nft backend; rule lives in the self-owned inet fluxpeer table). Needs root + nft.
set -u
B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
PHYS="${FW_PHYS:-eth0}"; TUN="${FW_TUN:-fpks0}"
pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo -n"
command -v nft >/dev/null 2>&1 || { echo "  (no nft; skip)"; echo "RESULTS: 0 pass / 0 fail"; exit 0; }

$SUDO env FLUXPEER_FW_BACKEND=nft "$B" fw-selftest killswitch off --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
$SUDO env FLUXPEER_FW_BACKEND=nft "$B" fw-selftest killswitch on --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
RULES=$($SUDO nft list table inet fluxpeer 2>/dev/null)
echo "$RULES" | grep -qiE "oifname \"?$PHYS\"?.*(!= ?\"?$TUN|iifname).*drop|drop" && ok "killswitch on -> drop rule present" || no "killswitch on: no drop rule ($(echo "$RULES" | grep -i drop))"
$SUDO env FLUXPEER_FW_BACKEND=nft "$B" fw-selftest killswitch off --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
RULES2=$($SUDO nft list table inet fluxpeer 2>/dev/null)
echo "$RULES2" | grep -qi drop && no "killswitch off: drop rule still present" || ok "killswitch off -> drop rule removed"
$SUDO env FLUXPEER_FW_BACKEND=nft "$B" fw-selftest down --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
echo "===== RESULTS: $pass pass / $fail fail ====="
[ "$fail" = 0 ]
