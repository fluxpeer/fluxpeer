# Licensing

fluxpeer is **open core**. Different parts carry different licenses by design:

| Component | Where | License |
|---|---|---|
| **Core** — engine, CLI, SDK, control-server, relay-server, node, router-agent, api-schema | this repo | **BSD-3-Clause** (permissive) |
| **GUI clients** — mobile app (`app/`), desktop app (`desktop/`) | this repo | **AGPL-3.0-or-later** (copyleft) |
| **Managed/commercial plane** — billing, accounts, IP marketplace, provisioning, admin & customer portals, marketing site | separate private repo | **Proprietary** (not open) |
| **Brand** — the "fluxpeer" name, logos, and marks | — | Trademark — see [TRADEMARKS.md](TRADEMARKS.md) |

## Why this split

- **The core is BSD-3** so anyone can embed, self-host, and build on the protocol and data plane with minimal friction. In a world where networking tech is commoditized, an open, auditable core is a *trust* asset, not a liability.
- **The clients are AGPL-3.0** because the installed app is the real trust boundary for a no-logs claim — it must be auditable. AGPL keeps that benefit intact: anyone may use, study, and modify the clients, but a party that distributes a modified client (including over a network) must release their source under the same terms. This prevents a closed, white-labeled fork from free-riding while keeping the clients fully open and verifiable.
- **The managed plane stays proprietary** because that is the business: running the service well — provisioning, IP supply and quality, billing, operations, support. Open source is the top of the funnel for it, not a competitor to it.

## Per-file headers

Use SPDX identifiers at the top of source files:

- Core: `// SPDX-License-Identifier: BSD-3-Clause`
- Clients (`app/`, `desktop/`): `// SPDX-License-Identifier: AGPL-3.0-or-later`

Full license texts: [`LICENSE`](LICENSE) (BSD-3-Clause) and [`LICENSE-AGPL-3.0.txt`](LICENSE-AGPL-3.0.txt) (AGPL-3.0).
A commercial license for the clients (to use them without AGPL obligations) is available — contact licensing@fluxpeer.org.
