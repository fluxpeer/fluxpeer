# fluxpeer protocol & API versioning

Source of truth for cross-component compatibility. The data-plane constants live
in `engine/core/fp-node-core/src/protocol.rs`; the control-plane API version and
config epoch are owned by `control-server`.

## Versioned surfaces

| Field | Owner | Where it travels | Current |
|---|---|---|---|
| `client_protocol_version` | engine (client) | data-plane handshake frame (`Handshake.protocol_version`) | 1 |
| `server_protocol_version` | engine (server) | server build / capabilities | 1 |
| `relay_protocol_version` | relay-server | relay handshake | 1 |
| `server_api_version` | control-server | HTTP `/api/v1`, response meta | v1 |
| `config_epoch` | control-server | every config push (WS/HTTPS) | u64, monotonic |

## Floors

| Field | Current | Meaning |
|---|---|---|
| `min_supported_client_protocol_version` | 1 | server rejects older clients |
| `min_supported_server_protocol_version` | 1 | client rejects older servers |

`PROTOCOL_VERSION_UNKNOWN = 0` is the sentinel for a peer that did not advertise
a version (predates versioning). It is **not** accepted by the `*_supported`
checks.

## Bump rules

- Increment a `*_PROTOCOL_VERSION` on **any** wire-format change to that surface.
- Raise a `MIN_SUPPORTED_*` only when intentionally dropping backward compat.
- `config_epoch` increments on every coordination-plane config change; clients
  apply only strictly-newer epochs and **force a full sync on reconnect** to
  converge.

## Handshake enforcement (implemented)

- Client stamps `Handshake.protocol_version = CLIENT_PROTOCOL_VERSION`.
- Server checks `client_version_supported(protocol_version)`; if unsupported it
  logs a warning and drops the connection (no handshake response).
- The field is `#[serde(default)]`, so a versionless peer deserializes to
  `UNKNOWN (0)` and is cleanly rejected by the floor check.

## Compatibility check (client→server, control plane)

On connect the client should verify against the control-server:
`server_api_version`, `relay_protocol_version`, and the `min_supported_*` floors,
and surface "upgrade client / upgrade server" guidance.
