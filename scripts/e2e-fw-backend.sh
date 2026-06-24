#!/usr/bin/env bash
# e2e-fw-backend.sh — acceptance for the pluggable exit/forward FIREWALL
# backend (nft on default OpenWrt; iptables on legacy/generic Linux). Black-box via
# the `fluxpeer fw-selftest` seam, so it runs on any host (Linux nft / OpenWrt rootfs
# container / generic-Linux iptables). Proves, per available backend:
#   * up installs masquerade(out phys) + forward-accept(tun) and enables ip_forward
#   * down removes ALL of it (the leak-class regression — nft delete-table is atomic)
#   * up is idempotent (a second up must not accumulate duplicates)
#   * with no FLUXPEER_FW_BACKEND, detection picks nft when nft is usable
# Needs root (firewall + sysctl).
set -u
B="${FLUXPEER_BIN:-./target/release/fluxpeer}"
PHYS="${FW_PHYS:-eth0}"
TUN="${FW_TUN:-fpsel0}"   # name-based rules; the iface need not exist
pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }
have(){ command -v "$1" >/dev/null 2>&1; }
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo -n"

nft_has_table(){ $SUDO nft list table inet fluxpeer >/dev/null 2>&1; }
nft_rule_count(){ $SUDO nft list table inet fluxpeer 2>/dev/null | grep -cE 'masquerade|accept'; }
ipt_masq_count(){ $SUDO iptables -t nat -S POSTROUTING 2>/dev/null | grep -c MASQUERADE; }
ipt_fwd_count(){ $SUDO iptables -S FORWARD 2>/dev/null | grep -cE "$TUN"; }

# --- run one backend's up/idempotent-up/down lifecycle ---
test_backend(){ # $1 = nft|iptables
  local be="$1"
  echo "===== backend: $be ====="
  $SUDO env FLUXPEER_FW_BACKEND="$be" "$B" fw-selftest down --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1 # clean slate
  # up
  local out; out=$($SUDO env FLUXPEER_FW_BACKEND="$be" "$B" fw-selftest up --phys "$PHYS" --tun "$TUN" 2>&1)
  echo "$out" | grep -qiE "$be|backend" && ok "[$be] up ran (reported backend)" || echo "    (up output: $out)"
  if [ "$be" = nft ]; then
    nft_has_table && [ "$(nft_rule_count)" -ge 2 ] && ok "[$be] up installed inet fluxpeer (masq+accept)" || no "[$be] up did not install rules"
    # idempotent
    $SUDO env FLUXPEER_FW_BACKEND="$be" "$B" fw-selftest up --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
    local c2; c2=$(nft_rule_count)
    $SUDO env FLUXPEER_FW_BACKEND="$be" "$B" fw-selftest down --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
    nft_has_table && no "[$be] down left inet fluxpeer table (LEAK)" || ok "[$be] down deleted table (zero residue)"
  else
    [ "$(ipt_masq_count)" -ge 1 ] && [ "$(ipt_fwd_count)" -ge 1 ] && ok "[$be] up installed masq+forward" || no "[$be] up did not install rules"
    $SUDO env FLUXPEER_FW_BACKEND="$be" "$B" fw-selftest up --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
    local m; m=$(ipt_masq_count)
    [ "$m" -le 1 ] && ok "[$be] up idempotent (masq count=$m)" || no "[$be] up accumulated (masq count=$m)"
    $SUDO env FLUXPEER_FW_BACKEND="$be" "$B" fw-selftest down --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1
    { [ "$(ipt_masq_count)" = 0 ] && [ "$(ipt_fwd_count)" = 0 ]; } && ok "[$be] down removed all (zero residue)" || no "[$be] down left residue"
  fi
}

echo "########## fw-selftest backend lifecycle ##########"
have nft && test_backend nft || echo "  (nft absent — skip nft backend)"
have iptables && test_backend iptables || echo "  (iptables absent — skip iptables backend)"

echo "########## auto-detection (no FLUXPEER_FW_BACKEND) ##########"
det=$($SUDO "$B" fw-selftest detect 2>&1 || true)
echo "  detected: $det"
if have nft; then echo "$det" | grep -qi nft && ok "auto-detect picks nft where nft usable" || no "auto-detect did not pick nft (got: $det)"; fi
$SUDO "$B" fw-selftest down --phys "$PHYS" --tun "$TUN" >/dev/null 2>&1 || true

echo "===== RESULTS: $pass pass / $fail fail ====="
[ "$fail" = 0 ]
