# sdk

Official fluxpeer SDKs: typed clients for the control-server `/api/v1`.

- `rust/` — **`fluxpeer-sdk`**: typed async client (`Client`) for the
  control-server `/api/v1` (network/invite/device/config/route/relay/resolve).
  Used by the `fp` CLI; embeddable in third-party tools. Verified via the CLI's
  integration test against a live in-process server.

Go / TypeScript SDKs are planned, to be generated from `api-schema/openapi.yaml`.
