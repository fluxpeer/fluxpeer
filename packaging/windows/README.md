# Windows packaging

Same split as the other platforms: the **daemon** (`fluxpeer up`) as a Windows
service, and the **desktop GUI** (`fluxpeer-desktop.exe`, unprivileged) talking to
it over `127.0.0.1` + the token in `%ProgramData%\fluxpeer\daemon.token`.

## Install

```powershell
cargo build --release -p fluxpeer            # on a Windows build host
# elevated PowerShell:
powershell -ExecutionPolicy Bypass -File packaging\windows\install.ps1 -Binary .\target\release\fluxpeer.exe
```

`install.ps1`:
- copies `fluxpeer.exe` to `C:\Program Files\fluxpeer`,
- downloads **wintun.dll** (the TUN driver) for the host arch into that dir,
- registers the `fluxpeer` service (NSSM if present — recommended — else `sc.exe`).

The GUI bundles no driver; run `fluxpeer-desktop.exe` directly (a proper installer /
Start-menu shortcut + code-signing is a later step, like macOS notarization).

## Status / remaining data-plane work

The packaging + service wiring above is complete. The **node TUN backend on
Windows uses wintun** (`wintun.dll`, fetched above) rather than the Linux
`/dev/net/tun` path. The cross-platform TUN abstraction in `node/` is the
remaining implementation work to make the data plane run on Windows; it is
isolated to the device I/O layer (transports, crypto, control are platform-
agnostic). Until then, Windows builds the binaries and runs the control/relay
roles; the on-device tunnel needs the wintun backend wired in.

Code-signing: sign `fluxpeer.exe` / `fluxpeer-desktop.exe` with an Authenticode
cert (`signtool sign /fd sha256 /tr <timestamp> ...`) for SmartScreen trust.
