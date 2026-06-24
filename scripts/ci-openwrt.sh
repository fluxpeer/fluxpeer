#!/usr/bin/env bash
# OpenWrt-focused local CI helper. It runs only checks that are executable on the
# current host and prints explicit SKIP reasons for everything else.
set -u
set -o pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENWRT_ROOT="$ROOT/../fluxpeer-openwrt"

PASS=0
FAIL=0
SKIP=0

have() {
  command -v "$1" >/dev/null 2>&1
}

is_linux() {
  [ "$(uname -s)" = "Linux" ]
}

can_root() {
  [ "$(id -u)" = 0 ] || sudo -n true >/dev/null 2>&1
}

stage() {
  local name="$1"
  shift
  echo
  echo "==> RUN: $name"
  if "$@"; then
    echo "PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

skip() {
  echo
  echo "SKIP: $1"
  echo "      reason: $2"
  SKIP=$((SKIP + 1))
}

run_bash_syntax() {
  bash -n \
    "$SCRIPT_PATH" \
    "$OPENWRT_ROOT/files/etc/init.d/fluxpeer" \
    "$OPENWRT_ROOT/files/etc/uci-defaults/80-fluxpeer" \
    "$OPENWRT_ROOT/files/usr/libexec/rpcd/fluxpeer" \
    "$OPENWRT_ROOT/test/rpcd-smoke.sh" \
    "$OPENWRT_ROOT/test/luci-check.sh"
}

run_json_checks() {
  python3 -m json.tool "$OPENWRT_ROOT/files/usr/share/rpcd/acl.d/fluxpeer.json" >/dev/null
  python3 -m json.tool "$OPENWRT_ROOT/luci-app-fluxpeer/root/usr/share/luci/menu.d/luci-app-fluxpeer.json" >/dev/null
  python3 -m json.tool "$OPENWRT_ROOT/luci-app-fluxpeer/root/usr/share/rpcd/acl.d/luci-app-fluxpeer.json" >/dev/null
}

run_brand_check() {
  ! grep -RInE 'cukeflux|cuke168' \
    "$OPENWRT_ROOT/README.md" \
    "$OPENWRT_ROOT/files" \
    "$OPENWRT_ROOT/package" \
    "$OPENWRT_ROOT/luci-app-fluxpeer" >/dev/null 2>&1
}

run_l1_clippy() {
  cargo clippy -p fluxpeer-node -p fluxpeer-control-server -- -D warnings
}

run_rpcd_smoke() {
  podman run --rm --platform linux/arm64 \
    -v "$OPENWRT_ROOT/files/usr/libexec/rpcd/fluxpeer:/usr/libexec/rpcd/fluxpeer:ro" \
    -v "$OPENWRT_ROOT/test/rpcd-smoke.sh:/tmp/rpcd-smoke.sh:ro" \
    docker.io/openwrt/rootfs:aarch64_generic-23.05.5 \
    /bin/sh /tmp/rpcd-smoke.sh
}

run_ash_syntax_in_openwrt() {
  podman run --rm --platform linux/arm64 \
    -v "$OPENWRT_ROOT/files:/work/files:ro" \
    docker.io/openwrt/rootfs:aarch64_generic-23.05.5 \
    /bin/ash -c 'ash -n /work/files/etc/init.d/fluxpeer && ash -n /work/files/etc/uci-defaults/80-fluxpeer && ash -n /work/files/usr/libexec/rpcd/fluxpeer'
}

release_bin() {
  if [ -n "${FLUXPEER_BIN:-}" ] && [ -x "$FLUXPEER_BIN" ]; then
    printf '%s\n' "$FLUXPEER_BIN"
  elif [ -x "$ROOT/target/release/fluxpeer" ]; then
    printf '%s\n' "$ROOT/target/release/fluxpeer"
  else
    return 1
  fi
}

run_firewall_e2e() {
  local bin
  bin="$(release_bin)"
  FLUXPEER_BIN="$bin" "$ROOT/scripts/e2e-fw-backend.sh"
}

run_subnet_e2e() {
  local bin
  bin="$(release_bin)"
  FLUXPEER_BIN="$bin" "$ROOT/scripts/e2e-subnet-nft.sh"
}

run_aarch64_build() {
  cargo zigbuild --release --target aarch64-unknown-linux-musl -p fluxpeer
}

run_mipsel_build() {
  RUSTFLAGS="${RUSTFLAGS:--C link-arg=-msoft-float}" \
  CFLAGS_mipsel_unknown_linux_musl="${CFLAGS_mipsel_unknown_linux_musl:--msoft-float}" \
  CXXFLAGS_mipsel_unknown_linux_musl="${CXXFLAGS_mipsel_unknown_linux_musl:--msoft-float}" \
  cargo +nightly zigbuild \
    -Z build-std=std,panic_abort \
    --release \
    --target mipsel-unknown-linux-musl \
    -p fluxpeer
}

cd "$ROOT" || exit 1

echo "OpenWrt CI root: $ROOT"
echo "OpenWrt package root: $OPENWRT_ROOT"

if [ ! -d "$OPENWRT_ROOT" ]; then
  echo "FAIL: missing OpenWrt tree: $OPENWRT_ROOT" >&2
  exit 1
fi

if have bash; then
  stage "bash syntax" run_bash_syntax
else
  skip "bash syntax" "bash is not installed"
fi

if have python3; then
  stage "JSON files" run_json_checks
else
  skip "JSON files" "python3 is not installed"
fi

stage "brand residue" run_brand_check

if have cargo; then
  stage "L1 clippy subset" run_l1_clippy
else
  skip "L1 clippy subset" "cargo is not installed"
fi

if have node; then
  stage "L5 LuCI static" bash "$OPENWRT_ROOT/test/luci-check.sh"
else
  skip "L5 LuCI static" "node is not installed"
fi

if have podman; then
  stage "OpenWrt ash syntax" run_ash_syntax_in_openwrt
  stage "L2 rpcd OpenWrt smoke" run_rpcd_smoke
else
  skip "OpenWrt ash syntax" "podman is not installed"
  skip "L2 rpcd OpenWrt smoke" "podman is not installed"
fi

if is_linux; then
  if can_root; then
    if have nft; then
      if release_bin >/dev/null 2>&1; then
        stage "L2 firewall e2e" run_firewall_e2e
      else
        skip "L2 firewall e2e" "no executable FLUXPEER_BIN and no target/release/fluxpeer"
      fi
    else
      skip "L2 firewall e2e" "nft is not installed"
    fi

    if have nft && have ip && have curl && have python3; then
      if release_bin >/dev/null 2>&1; then
        stage "L3 subnet nft e2e" run_subnet_e2e
      else
        skip "L3 subnet nft e2e" "no executable FLUXPEER_BIN and no target/release/fluxpeer"
      fi
    else
      skip "L3 subnet nft e2e" "requires nft, ip, curl, and python3"
    fi
  else
    skip "L2 firewall e2e" "Linux root or passwordless sudo is required"
    skip "L3 subnet nft e2e" "Linux root or passwordless sudo is required"
  fi
else
  skip "L2 firewall e2e" "Linux-only"
  skip "L3 subnet nft e2e" "Linux-only"
fi

if [ "${CI_OPENWRT_AARCH64:-0}" = "1" ]; then
  if have cargo && have cargo-zigbuild; then
    stage "optional aarch64 musl build" run_aarch64_build
  else
    skip "optional aarch64 musl build" "requires cargo and cargo-zigbuild"
  fi
else
  skip "optional aarch64 musl build" "set CI_OPENWRT_AARCH64=1 to run"
fi

if [ "${CI_OPENWRT_MIPSEL:-0}" = "1" ]; then
  if have cargo && have cargo-zigbuild && rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    stage "optional mipsel soft-float build" run_mipsel_build
  else
    skip "optional mipsel soft-float build" "requires cargo, cargo-zigbuild, and nightly toolchain"
  fi
else
  skip "optional mipsel soft-float build" "set CI_OPENWRT_MIPSEL=1 to run"
fi

echo
echo "OpenWrt CI summary: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
