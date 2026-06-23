# macOS packaging

Two pieces: the **daemon** (`fluxpeer up`, runs as root for the TUN device) and
the **desktop GUI** (`Fluxpeer.app`, unprivileged, talks to the daemon over
`127.0.0.1` + the token in `/etc/fluxpeer/daemon.token`).

## Daemon (LaunchDaemon)

```bash
# build the unified binary (on a build host / locally with cargo)
cargo build --release -p fluxpeer
sudo packaging/macos/install-daemon.sh target/release/fluxpeer
```

Installs `/usr/local/bin/fluxpeer` + `/Library/LaunchDaemons/org.fluxpeer.daemon.plist`
and loads it. Logs at `/var/log/fluxpeer.log`. Uninstall: `launchctl unload`, then
remove the plist and binary.

## Desktop app

```bash
packaging/macos/make-app.sh            # → target/Fluxpeer.app (icon from assets/mark.svg)
CODESIGN_ID="Developer ID Application: Your Name (TEAMID)" packaging/macos/make-app.sh
```

## Signing & notarization (for distribution)

Unsigned apps are Gatekeeper-blocked on other Macs. To distribute:

1. **Sign** — `CODESIGN_ID=… make-app.sh` (uses `--options runtime` hardened runtime).
2. **Notarize**:
   ```bash
   ditto -c -k --keepParent target/Fluxpeer.app Fluxpeer.zip
   xcrun notarytool submit Fluxpeer.zip --apple-id you@example.com \
     --team-id TEAMID --password "app-specific-pw" --wait
   xcrun stapler staple target/Fluxpeer.app
   ```
3. The daemon binary, if shipped separately, should also be signed + notarized.

> A self-signed/unsigned build runs locally for development (right-click → Open).
> Distribution requires an Apple Developer ID — that step is the maintainer's.
