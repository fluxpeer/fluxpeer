# fluxpeer

Open-source, self-hostable **mesh networking** — connect your own devices, servers,
and private services into one secure network. Direct peer-to-peer when it can, with
automatic relay fallback when it can't, and continuous path selection in between.
WireGuard-compatible, fast, and auditable end to end. **Not** a public-exit VPN by
default — it's split-tunnel private networking (you choose what's routed).

You can self-host the entire stack from this repository. A managed service
(**fluxpeer.com**) runs the same engine for those who'd rather not run servers — that's
optional convenience, not lock-in.

## Open core

| Part | License |
|---|---|
| Engine, CLI, SDK, control/relay/node servers (this repo) | **BSD-3-Clause** |
| GUI clients (mobile, desktop) | **AGPL-3.0** |
| The managed/commercial plane (billing, IP marketplace, hosted infra) | proprietary, separate |

See [`LICENSING.md`](LICENSING.md) and [`TRADEMARKS.md`](TRADEMARKS.md). The data plane
is open source, so the no-logs claim is verifiable, not just asserted.

## Repository layout

```
engine/              Rust mesh engine (WireGuard-compatible data plane)
  crypto/            Noise / Curve25519 cryptography (boringtun-derived)
  transport/         pluggable transports: udp, tcp, tcp-bond, anytls, demux
  net/               TUN, NAT traversal (disco/magicsock/netcheck), path selection
  core/              node engine core
  sys/               FFI sys crates (server + client)
  vendor/            wintun (Windows TUN driver)
fluxpeer-bin/        the unified `fluxpeer` binary (control/relay/node/cli subcommands)
control-server/      coordination plane: networks, devices, invites, peers, routes
relay-server/        self-built relay (DERP-style, ciphertext-only)
node/                node / gateway runtime + the `up` daemon
cli/                 management CLI (`fp`)
sdk/rust/            Rust SDK (control client + wg.conf import)
api-schema/          OpenAPI + protocol/versioning docs
packaging/           Linux / macOS / Windows packaging (daemon + app bundling)
deploy/              docker-compose + deployment docs
```

End-user **clients live in separate repos** (this repo is the BSD-3 core):

| Repo | What | License |
|---|---|---|
| `fluxpeer-desktop` | desktop GUI (iced) | AGPL-3.0 |
| `fluxpeer-app` | mobile app (Flutter) | AGPL-3.0 |
| `fluxpeer-admin` | admin web UI (Svelte) | AGPL-3.0 |
| `fluxpeer.org` | marketing site (Svelte) | — |
| `fluxpeer-openwrt` | OpenWrt router agent | BSD-3 |

They build against this core via the published `fluxpeer-sdk` / FFI crates.

## Build

```bash
cargo build --workspace
cargo test  --workspace
```

The GUI clients live in their own repos (see the table above) and build against this
core via the `fluxpeer-sdk` / FFI crates.

## Contributing & security

Contributions welcome under the licenses above. Please report security issues
privately — see [`SECURITY.md`](SECURITY.md).

---

fluxpeer is part of the **openprx** family. Status: actively developed; interfaces may
change before a tagged 1.0.
