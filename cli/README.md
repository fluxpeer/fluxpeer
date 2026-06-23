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
