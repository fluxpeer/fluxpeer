#!/usr/bin/env bash
# fluxpeer — cross-build the mobile node engine into Android jniLibs.
#
#   scripts/build-android.sh [--debug] [--abi arm64-v8a,armeabi-v7a,x86_64]
#
# Produces libfp_node_client_sys.so per ABI under
#   ../fluxpeer-app/android/app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/
# which Gradle bundles into the APK; Kotlin loads it via System.loadLibrary
# ("fp_node_client_sys") and calls the JNI shims in src/ffi/android.rs.
#
# Requires: cargo-ndk (`cargo install cargo-ndk`) + an installed Android NDK.
# The engine is built WITH default features (incl. `enroll`), so the resulting
# .so carries fp_enroll + the Java_..._enroll JNI shim.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

PROFILE="release"
PROFILE_FLAG="--release"
ABIS="arm64-v8a,armeabi-v7a,x86_64"
while [ $# -gt 0 ]; do
  case "$1" in
    --debug) PROFILE="debug"; PROFILE_FLAG="" ;;
    --abi) ABIS="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# Auto-detect the NDK if ANDROID_NDK_HOME is unset (pick the highest version).
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  if [ -d "$sdk/ndk" ]; then
    ANDROID_NDK_HOME="$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1)"
    export ANDROID_NDK_HOME
  fi
fi
if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "✗ Android NDK not found. Set ANDROID_NDK_HOME or install via Android Studio." >&2
  exit 1
fi
echo "→ NDK: $ANDROID_NDK_HOME"

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "✗ cargo-ndk not installed.  cargo install cargo-ndk" >&2
  exit 1
fi

# Map cargo-ndk ABI names → rustup target triples and ensure they're installed.
declare -A TRIPLES=(
  [arm64-v8a]=aarch64-linux-android
  [armeabi-v7a]=armv7-linux-androideabi
  [x86_64]=x86_64-linux-android
  [x86]=i686-linux-android
)
NDK_ARGS=()
IFS=',' read -ra LIST <<< "$ABIS"
for abi in "${LIST[@]}"; do
  triple="${TRIPLES[$abi]:-}"
  [ -z "$triple" ] && { echo "✗ unknown ABI: $abi" >&2; exit 2; }
  rustup target add "$triple" >/dev/null 2>&1 || true
  NDK_ARGS+=(-t "$abi")
done

OUT="../fluxpeer-app/android/app/src/main/jniLibs"
mkdir -p "$OUT"

echo "→ building fp-node-client-sys ($PROFILE) for: $ABIS"
cargo ndk "${NDK_ARGS[@]}" -o "$OUT" build --manifest-path Cargo.toml $PROFILE_FLAG -p fp-node-client-sys || exit 1

echo "✓ jniLibs:"
find "$OUT" -name 'libfp_node_client_sys.so' -exec sh -c 'echo "    $1 ($(du -h "$1" | cut -f1))"' _ {} \;
