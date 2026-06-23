# Contributing to fluxpeer

Thanks for your interest! fluxpeer is open core — contributions are welcome under
the licenses below.

## Licensing of contributions

By submitting a change you agree it is licensed under the license of the area you
touch:

- **Core** (engine, `crates/*`, `api-schema`, `router-agent`) — **BSD-3-Clause**
- **GUI clients** (`clients/desktop`, `clients/mobile`) — **AGPL-3.0-or-later**

Add the matching SPDX header to new source files:

```
// SPDX-License-Identifier: BSD-3-Clause          (core)
// SPDX-License-Identifier: AGPL-3.0-or-later      (clients)
```

See [`LICENSING.md`](LICENSING.md) and [`TRADEMARKS.md`](TRADEMARKS.md).

## Development

```bash
cargo build --workspace
cargo test  --workspace --exclude fluxpeer-desktop   # desktop test binary links GTK/X11
cargo clippy --workspace -- -D warnings              # zero-warning gate — must be clean
```

The desktop GUI is a standalone crate (its own deps):
`cargo build --manifest-path clients/desktop/Cargo.toml`.

Full regression (clippy + tests + netns real-tunnel e2e + Windows cross-check) runs
via `scripts/ci.sh` on a Linux host with root — see [`docs/CI.md`](docs/CI.md).

## Code style & invariants

- **`cargo fmt` is NOT used** — the codebase is hand-formatted. Match the style of
  the surrounding code; don't reformat unrelated lines.
- **No `std::sync::{Mutex,RwLock,Condvar}`** in production — use `parking_lot::*`
  (sync) or `tokio::sync::*` (async). Enforced by `clippy.toml`.
- **Zero panics in production code**: `unwrap`/`expect`/`panic!`/`dbg!` are allowed
  only in tests.
- Keep the binary small — gate optional/heavy paths behind cargo features.

## Workflow

1. Branch off `main` (short-lived feature branch).
2. Make the change; keep clippy zero-warning and tests green.
3. Open a PR with a clear description (what + why); link any issue.
4. Squash/rebase merge after review + passing CI. `main` is protected and always
   releasable.

## Security

Please report vulnerabilities **privately** — do not open a public issue. See
[`SECURITY.md`](SECURITY.md).
