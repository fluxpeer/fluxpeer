# Changelog

All notable changes to fluxpeer are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/). Interfaces may change before a tagged 1.0.

## [Unreleased]

### Changed
- Settled on a flat core workspace layout (engine + server crates + cli + sdk at
  the top level); the GUI clients live in their own separate repositories.

### Removed
- Dropped unused crates that were never wired into the data plane:
  `fp-route`, `fp-magicsock`, `fp-rpc-crypto`, and `fp-transport-demux`.

## [0.1.0]

### Added
- Initial public release: WireGuard-compatible mesh data plane with a connection
  ladder (UDP-direct → TCP-direct → relay) and continuous path selection.
- A flat core workspace: the `fp-*` engine crates, `control-server` (coordination
  plane), `relay-server` (DERP-style, ciphertext-only), the `node`/gateway runtime,
  the management CLI, and the Rust SDK.
- Self-host packaging for Linux / macOS / Windows.

The GUI clients (desktop iced, mobile Flutter, Svelte admin) ship from their own
separate repositories and are not part of this core workspace.
