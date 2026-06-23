#!/usr/bin/env bash
# fluxpeer — cross-build the mobile node engine into an iOS xcframework.
#
#   scripts/build-ios.sh [--debug]
#
# Produces ../fluxpeer-app/ios/Frameworks/Fluxpeer.xcframework containing the static lib for
# BOTH iOS device (aarch64-apple-ios) and simulator (aarch64-apple-ios-sim) —
# an xcframework, not a lipo'd fat lib, because device + sim are both arm64 and
# can't coexist in one .a. Bundles the cbindgen header + a module map so the
# NetworkExtension target can `import FluxpeerFFI` and call fp_* directly.
#
# Requires: Xcode (xcodebuild) + the Rust apple-ios targets (auto-added).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

PROFILE="release"; FLAG="--release"
[ "${1:-}" = "--debug" ] && { PROFILE="debug"; FLAG=""; }

command -v xcodebuild >/dev/null 2>&1 || { echo "✗ xcodebuild not found (install Xcode)" >&2; exit 1; }

DEVICE=aarch64-apple-ios
SIM=aarch64-apple-ios-sim
for t in "$DEVICE" "$SIM"; do rustup target add "$t" >/dev/null 2>&1 || true; done

# Build ONLY the staticlib (.a) — iOS links it into the app. We skip the cdylib
# crate-type on purpose: its link step pulls libc stack-probe / compiler-rt
# symbols (e.g. ___chkstk_darwin via zstd-sys) that only resolve at the final
# Xcode app link, so a standalone cdylib link spuriously fails. `cargo rustc
# --crate-type staticlib` overrides the manifest's crate-type for just this build.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}"
echo "→ building fp-node-client-sys staticlib ($PROFILE, iOS $IPHONEOS_DEPLOYMENT_TARGET) for $DEVICE + $SIM"
for t in "$DEVICE" "$SIM"; do
  cargo rustc --manifest-path Cargo.toml $FLAG --target "$t" -p fp-node-client-sys --crate-type staticlib || exit 1
done

LIB=libfp_node_client_sys.a
GEN_HEADER=engine/sys/fp-node-client-sys/fp_node_client_sys.h
[ -f "$GEN_HEADER" ] || { echo "✗ header not generated: $GEN_HEADER" >&2; exit 1; }

# Headers dir for the xcframework: the cbindgen header + a module map. The iOS
# build always enables `enroll`, so define FP_FEATURE_ENROLL up front to expose
# fp_enroll/fp_gateway without each consumer passing -D.
HDR=target/ios-headers
rm -rf "$HDR"; mkdir -p "$HDR"
{ echo "#define FP_FEATURE_ENROLL 1"; cat "$GEN_HEADER"; } > "$HDR/fp_node_client_sys.h"
cat > "$HDR/module.modulemap" <<'EOF'
module FluxpeerFFI {
    header "fp_node_client_sys.h"
    export *
}
EOF

OUT=../fluxpeer-app/ios/Frameworks/Fluxpeer.xcframework
rm -rf "$OUT"; mkdir -p "$(dirname "$OUT")"
xcodebuild -create-xcframework \
  -library "target/$DEVICE/$PROFILE/$LIB" -headers "$HDR" \
  -library "target/$SIM/$PROFILE/$LIB" -headers "$HDR" \
  -output "$OUT" || exit 1

echo "✓ $OUT"
find "$OUT" -name "$LIB" -exec sh -c 'echo "    $1 ($(du -h "$1" | cut -f1))"' _ {} \;
