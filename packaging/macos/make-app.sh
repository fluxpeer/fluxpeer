#!/usr/bin/env bash
# Build Fluxpeer.app — the desktop GUI bundled with the bagua icon.
# Usage: packaging/macos/make-app.sh [output.app]
#   CODESIGN_ID="Developer ID Application: …"  → sign the bundle (optional)
#
# The desktop client (AGPL-3.0) is a standalone crate excluded from the core
# BSD workspace, so it's built via its own manifest and its own target dir.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
APP="${1:-$REPO/target/Fluxpeer.app}"
cd "$REPO"

echo "==> building desktop (release)"
cargo build -q --release --manifest-path ../fluxpeer-desktop/Cargo.toml

echo "==> rasterizing icon from assets/mark.svg"
TMP="$(mktemp -d)"
ICONSET="$TMP/AppIcon.iconset"
cargo run -q --manifest-path ../fluxpeer-desktop/Cargo.toml --example icongen -- "$REPO/assets/mark.svg" "$ICONSET" >/dev/null

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
# Build artifact is fluxpeer-desktop (avoids the case-insensitive clash with the
# `fluxpeer` CLI); inside the bundle it's named Fluxpeer (CFBundleExecutable).
cp "$REPO/../fluxpeer-desktop/target/release/fluxpeer-desktop" "$APP/Contents/MacOS/Fluxpeer"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>            <string>fluxpeer</string>
  <key>CFBundleDisplayName</key>     <string>fluxpeer</string>
  <key>CFBundleIdentifier</key>      <string>org.fluxpeer.desktop</string>
  <key>CFBundleVersion</key>         <string>0.1.0</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleExecutable</key>      <string>fluxpeer-desktop</string>
  <key>CFBundleIconFile</key>        <string>AppIcon</string>
  <key>CFBundlePackageType</key>     <string>APPL</string>
  <key>LSMinimumSystemVersion</key>  <string>11.0</string>
  <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
PLIST

rm -rf "$TMP"
echo "built $APP"

if [[ -n "${CODESIGN_ID:-}" ]]; then
  echo "==> signing with $CODESIGN_ID"
  codesign --force --deep --options runtime --timestamp --sign "$CODESIGN_ID" "$APP"
  codesign --verify --deep --strict --verbose=2 "$APP"
  echo "signed. To notarize:  xcrun notarytool submit … (see README.md)"
else
  echo "note: set CODESIGN_ID to sign; unsigned apps are Gatekeeper-blocked on other Macs."
fi
