# cli (`fp`)

Management CLI for the control-server: networks / devices / invites / relays, plus `import` of `wg.conf` files.

```bash
export FLUXPEER_CONTROL_URL=http://127.0.0.1:8080   # or --server
fp network create <name>
fp network list
fp invite create <network-id> --max-uses 3 [--expires-at <unix>]
fp device list <network-id>
fp device revoke <device-id>
```

Thin HTTP client over `/api/v1`; logic in `Client` (integration-tested against a
live in-process server).

The server is selected by `--server`, then `FLUXPEER_CONTROL_URL` (existing primary
environment variable), then `FLUXPEER_SERVER` (alias), then the unique control URL in joined configurations (`--config-dir`, default `/etc/fluxpeer` on
Unix or `%PROGRAMDATA%\fluxpeer` on Windows). Missing or ambiguous configuration
is an error. If both environment variables are set and differ, network commands
fail before sending a request, even when `--server` is present. Equal values are
accepted. `import --dry-run` remains offline. `FLUXPEER_ADMIN_PASSWORD` is used
with an explicit flag or either environment variable; configuration discovery and SDK
`Client::new` are anonymous. Enrollment never sends an admin bearer, including
when called through `Client::with_password`. HTTP redirects are not followed.
