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

## Routes and member shutdown

The node uses wintun for device I/O and IP Helper for peer, split-default,
IPv6 guard and carrier bypass routes. No Linux `ip` executable is needed.
The configured adapter alias selects the TUN; physical paths use interface LUIDs.
Existing routes are preserved. A per-interface journal under
`%LOCALAPPDATA%\fluxpeer\routes` records only routes created by the member,
including pending creates, and is checked on the next start or explicit down.
Run recovery under the same service account as the original member. Conflicting
ownership or external modifications return an error instead of deleting a
foreign route. Preserve this directory when investigating residual routes.

Daemon down/shutdown sends a stop request through the member's private stdin
pipe. The member restores DNS, NAT and routes before acknowledging via process
exit. The daemon waits three seconds after sending the request, then forcibly
terminates a stalled member and reports `forced termination; network cleanup may
be incomplete`. Route recovery is attempted after reaping; a forced stop remains
an error because DNS/NAT cleanup has not been confirmed. Desktop Quit shows that
error and requires an explicit override to exit.

Windows cross-target check/clippy and host-side journal/IPC tests are covered;
Windows driver, route-table, service and DNS/NAT runtime verification is still
required on a Windows test host. Client kill-switch remains unsupported on
Windows. Service packaging behavior is not established by cross-compilation.

Code-signing: sign `fluxpeer.exe` / `fluxpeer-desktop.exe` with an Authenticode
cert (`signtool sign /fd sha256 /tr <timestamp> ...`) for SmartScreen trust.
