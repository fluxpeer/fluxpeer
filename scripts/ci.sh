#!/usr/bin/env bash
# fluxpeer regression / CI suite — run locally or from a CI runner.
#
#   scripts/ci.sh
#
# Stages (each pass/fail tracked; non-zero exit if ANY fails):
#   1. clippy  — zero-warning lint across the workspace
#   2. tests   — unit + integration (`cargo test --workspace`)
#   3. netns   — Linux-only single-host real-tunnel e2e (needs root/sudo)
#   4. windows — cross-compile check (only if the mingw toolchain is present)
#
# NOTE: `cargo fmt` is intentionally NOT enforced — the codebase is hand-formatted
# (cargo fmt would rewrite ~120 files), so style is reviewed, not gated.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Non-login shells (ssh 'cmd', CI runners) don't source the profile, so cargo may
# not be on PATH — pull it in if rustup installed it there.
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
# clippy isn't part of a minimal toolchain; install it if missing.
command -v cargo-clippy >/dev/null 2>&1 || rustup component add clippy >/dev/null 2>&1 || true

PASS=0
FAIL=0
SKIP=0
stage() {
  local name="$1"
  shift
  echo
  echo "━━━ $name ━━━"
  if "$@"; then
    echo "✓ $name"
    PASS=$((PASS + 1))
  else
    echo "✗ $name"
    FAIL=$((FAIL + 1))
  fi
}
skip() {
  echo
  echo "• skip: $1"
  SKIP=$((SKIP + 1))
}

# 1. Lint — must be zero-warning (the project's quality bottom line).
stage "clippy (zero-warning)" cargo clippy --workspace -- -D warnings

# 2. Unit + integration tests. fluxpeer-desktop is an iced GUI — its TEST binary
# links GTK/X11, absent on a headless CI runner (clippy still checks it, no link).
stage "tests (unit + integration)" cargo test --workspace --exclude fluxpeer-desktop

# 3. netns single-host e2e (real TUN tunnel): Linux + root only.
if [ "$(uname -s)" = "Linux" ]; then
  if [ "$(id -u)" = 0 ] || sudo -n true 2>/dev/null; then
    if cargo build --release -p fluxpeer; then
      FLUXPEER_BIN="$PWD/target/release/fluxpeer" stage "netns e2e regression" scripts/regression-netns.sh
      # Multi-peer mesh (≥3 nodes, each holds ≥2 peers): the ONLY stage that catches
      # receiver-index desync across workers / reconcile endpoint churn — invisible
      # in the 2-node test above.
      FLUXPEER_BIN="$PWD/target/release/fluxpeer" stage "multi-peer mesh regression (N=5)" scripts/regression-mesh-netns.sh
    else
      stage "netns e2e regression (release build)" false
    fi
  else
    skip "netns e2e (needs root/sudo)"
  fi
else
  skip "netns e2e (Linux-only)"
fi

# 4. Windows cross-compile check — only if the toolchain is installed.
if rustup target list --installed 2>/dev/null | grep -q x86_64-pc-windows-gnu \
  && command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
    CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
    CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++ \
    AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar
  stage "windows cross-check (fluxpeer)" cargo check --target x86_64-pc-windows-gnu -p fluxpeer
else
  skip "windows cross-check (no mingw/target)"
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "CI summary: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
