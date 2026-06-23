# packaging

Per-platform native packaging for the **client** side of fluxpeer — the privileged
**daemon** (`fluxpeer up`, owns the TUN device + a local control API on
`127.0.0.1`) and the unprivileged **desktop GUI** (`fluxpeer-desktop`, drives the
daemon over the loopback socket + the token in the config dir). Same split as
Tailscale: a system daemon + a user app.

> Server-side self-host (control-server / relay) lives in `../deploy` (Docker).

| Platform | Daemon | GUI | Files |
|----------|--------|-----|-------|
| **Linux** | systemd unit `fluxpeer.service` | run `fluxpeer-desktop` | `linux/` |
| **macOS** | LaunchDaemon `org.fluxpeer.daemon` | `Fluxpeer.app` (icon from `assets/mark.svg`) | `macos/` |
| **Windows** | service via NSSM/`sc.exe` + wintun | `fluxpeer-desktop.exe` | `windows/` |

Config dir holds per-network configs + `daemon.token` (the GUI reads it):
`/etc/fluxpeer` (Linux/macOS) · `%ProgramData%\fluxpeer` (Windows).

## Quick start

```bash
# Linux
cargo build --release -p fluxpeer
sudo packaging/linux/install.sh target/release/fluxpeer

# macOS
cargo build --release -p fluxpeer
sudo packaging/macos/install-daemon.sh target/release/fluxpeer   # daemon
packaging/macos/make-app.sh                                      # Fluxpeer.app

# Windows (elevated PowerShell)
cargo build --release -p fluxpeer
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1 -Binary .\target\release\fluxpeer.exe
```

Then onboard the device: `fluxpeer join "fp://join/…"` (token/QR from admin-lite).

## Build & signing notes

- Build the daemon on a host matching the target (or cross-compile; the project
  builds musl-static on the Linux build host). **Ship binaries, not source**, to
  deploy hosts.
- Distribution trust is the maintainer's step: macOS Developer-ID sign +
  notarize (`macos/README.md`), Windows Authenticode sign (`windows/README.md`).
- Windows on-device tunnel needs the **wintun** TUN backend wired into `node/`
  (see `windows/README.md`); packaging fetches the driver, the I/O layer is the
  remaining work.
