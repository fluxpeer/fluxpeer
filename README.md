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

## Relay directory identity

Register a relay with its actual AnyTLS transport identity in `node_id`, separate
from the control-server's generated directory `id` (`relay-N`). The registration
command accepts `--node-id`, or reads `FLUXPEER_RELAY_NODE_ID`, defaulting to
`fluxpeer-relay` just like the relay process. When registering from another host,
pass the identity used by that relay explicitly. For example, with your control
URL and admin credential supplied through the existing environment settings:

```bash
fp relay add eu relay.example.org:443 --anytls --node-id edge-eu \
  --stun-url relay.example.org:3478
```

Here the relay process must use `FLUXPEER_RELAY_NODE_ID=edge-eu`. SDK callers use
`register_relay_with_identity`; raw HTTP callers include `node_id` in `POST
/api/v1/relays`. Existing rows are migrated with a null identity. Missing/null
identities retain the legacy directory-id password derivation and produce a
client warning; that fallback does not repair an already mismatched old AnyTLS
registration. Re-register old rows with `fp relay add ... --node-id <actual-identity>`
using the relay process identity. Existing `node_id = NULL` rows still use the
legacy fallback; merely upgrading the node does not repair those rows. Explicit
identities must contain 1-128 visible ASCII characters;
whitespace, non-ASCII and oversized values are rejected.

Directory relay and STUN endpoints accept `host:port`, including DNS names and
bracketed IPv6 literals. Nodes resolve them asynchronously at bootstrap, with a
five-second timeout per lookup and up to eight entries in flight. All resolved
relay addresses enter failover, with IPv4 first and the resolver order preserved
within each address family; STUN selects IPv4 for the node's IPv4 UDP socket.
An invalid or unresolved relay endpoint causes its directory entry to be skipped
with a warning. A failing or malformed STUN endpoint only disables STUN for that
entry; its relay candidates remain usable. When directory lookup fails, a configured
relay or automatic direct mode can start immediately; a background retry uses bounded exponential backoff
(2–60 seconds). Once a usable directory is recovered, candidates enter the live
relay supervisor and exit selection is refreshed even at the same control epoch.
New relay bypass routes are applied before the candidates are published. Only
forced relay mode without a usable relay blocks and retries bootstrap. A healthy
directory is not periodically re-resolved. Recovery also queries refreshed STUN
on the existing data socket and reports its reflexive endpoint, preserving explicit
STUN/advertisement overrides. An empty relay list keeps direct fallback and silent
peer rekey recovery active even though the supervisor channels exist. IPv6-only
STUN is skipped while keeping the relay candidates.

## DNS ownership and restoration

On generic Linux, DNS settings are journaled by interface under
`/var/lib/fluxpeer/dns/state.json` before host changes. The directory is persistent
so a node restart retains the original resolver configuration. A process-shared
file lock serializes updates; the journal is replaced atomically. Owners record
PID, process start time and boot ID on Linux. Expired owners are pruned before
use; reused Linux PIDs cannot inherit ownership. Other Unix backends outside
Linux/macOS use `kill(pid, 0)` without a process-start-time guarantee. Across boots, snapshots of `/run` targets are
discarded, while original persistent files remain available for crash recovery.
Keep this state until all instances have restored DNS. The systemd unit declares
`StateDirectory=fluxpeer` so the journal remains writable with filesystem hardening.

The resolved backend snapshots each interface's DNS servers and search/routing
domains. If the service is unavailable, the fallback records the original bytes
of `/etc/resolv.conf` and the actual file backend used. Repeated updates retain
the original baseline. Cleanup follows those records even if backend detection
changes. Partial failures remain recorded for retry and are reported as host
apply errors.

When several interfaces use the shared resolver file, the latest setter supplies
the active servers. Clearing a non-current instance leaves the file untouched;
clearing the current instance restores the next active owner, and the last owner
restores the original bytes (or removes the file if it originally did not exist).
Writes use a same-directory temporary file, fsync and rename of the resolved
target; existing symlinks, target permissions and uid/gid are preserved. Bind mounts
that reject rename with EBUSY/EXDEV use truncate/write/fsync on the original inode.
Targets carrying a SELinux label also use the original inode to retain that label;
these in-place writes cannot provide rename atomicity. Dangling symlinks
retain their original link text and missing-target state. Fallback refuses known
NetworkManager/resolvconf/netconfig targets and ordinary files with the
`# Generated by NetworkManager` header; enable systemd-resolved or configure
DNS manually on those hosts. During full-tunnel operation every tick checks the
active file and repairs external content drift with a warning, backing repeated
repairs off from 2 to 60 seconds and warning only on repair attempts. Resolved,
OpenWrt and macOS DNS setters run only when desired settings change; an unchanged
completed OpenWrt apply performs no UCI commands or dnsmasq restart. During cleanup,
changed bytes or a retargeted symlink indicate external takeover: ownership is
released with a warning and the external configuration is left untouched. Check
the resolver manager and symlink configuration before enabling exit DNS again.

Exit DNS is applied only after the selected exit's host routes succeed. In split
mode, `FLUXPEER_MANAGE_DNS=1` uses the same ownership/cleanup path for admin DNS,
including multiple servers, without installing resolved's catch-all `~.` domain.
Startup recovery only runs for this interface's recorded effects; clear without
a journal creates no directories. Signal handlers are installed before initial
host effects, and graceful shutdown restores recorded state. macOS continues using its interface-scoped scutil
entry; Android DNS remains owned by VpnService. This change does not add an exit
DNS server. The core OpenWrt backend only gains an empty-state cleanup no-op;
the OpenWrt repository is unchanged.

## Client kill switch (Linux)

`kill_switch` is a local boolean, defaulting to `false`. It takes effect only
with `use_exit: "auto"` or an explicitly selected exit key. Configure it with
`fluxpeer kill-switch on|off --iface fp0`, the desktop **Kill switch** checkbox,
or the daemon `settings` command (`{"iface":"fp0","kill_switch":true}`). The
CLI edits local configuration and requires a tunnel restart, like `use-exit`;
daemon/desktop settings restart the member. It never enables full tunnel itself.
macOS and other unsupported hosts reject an active kill switch explicitly;
macOS pf integration is deferred to T-0042.

Kill-switch requires a single active membership on the host. Enabling it through
settings, set-config or `kill-switch on` is rejected while another membership is
up; disconnect the other memberships first. Starting a different membership is
rejected while a protected member is starting/running or its OUTPUT journal is
retained after exit: `kill-switch active on <iface>; disable it first`. Daemon
conflicts return `status: 409` in its JSON API and the desktop displays the error.
The check precedes configuration writes and process starts. File-based
`node run` also rejects another interface's retained guard. Single-member
operation and restarting the protected member are supported; there is no shared
allowlist that permits another membership through this guard.

Linux protects local OUTPUT with an instance-owned nft table or IPv4/IPv6
iptables chains. Exceptions are loopback, that instance's TUN, resolved control,
relay/STUN and peer carrier IPs, DHCP, IPv4/IPv6 link-local destinations, and IPv6
neighbor discovery. Ordinary DNS and user split-exclude CIDRs are not exceptions.
With no retained guard, bootstrap resolves all control, relay and STUN hostnames
using system DNS **before** installing OUTPUT protection. This initial resolution
phase is not protected. With a retained guard, startup restores cached carrier
addresses before contacting control and never falls back to ordinary DNS.
Protected HTTP clients use the same carrier cache through an exact-host resolver,
keep the original URL/Host/TLS identity, and disable environment proxy routing.

While an authenticated exit, its routes and full-tunnel DNS are available, carrier
names are refreshed through that tunnel. New carrier IPs and physical bypass
routes are added before old exceptions are removed. Without a usable exit,
resolution uses only saved pins. A new hostname or unreachable cached carrier
addresses retain the guard, retry with backoff, and expose
`kill_switch_dns_blocked: <host>` in `show --json`, daemon status and the desktop.
Connect an exit or disable kill-switch to resolve new carrier names. An outage
combined with a carrier hostname/IP change can require this explicit recovery;
there is no DNS exception, public resolver fallback, or new enrollment metadata.

Exit revocation, an unreachable exit, engine failure and configuration restarts
retain OUTPUT protection. A normal daemon/desktop disconnect or foreground
Ctrl-C releases it. Applying `use_exit: "off"` or `kill_switch: false` also
releases retained rules. Daemon shutdown releases guards for its memberships,
including stopped members. Failed cleanup is reported and its state remains
available for retry. State files under `/run/fluxpeer-firewall/*.output.json`
record the actual backend and carrier addresses. Adjacent `<iface>.carriers.json`
files hold each hostname's last successful IP set and timestamp; they use mode
0600, reject symlinks with O_NOFOLLOW, and are replaced atomically. Explicit down
or disabling protection deletes both the guard and its cache. Do not delete these
files to disable protection. They are runtime state, not reboot-persistent startup policy.

The node and daemon check unchanged policies every 30 seconds and restore missing
rules with a warning. The daemon also maintains guards after member failure.
After a standalone engine exits, retained rules remain, but reconciliation needs
a running daemon or a restarted engine. External firewall reloads can create a
gap until the next check; native firewall reload integration is not provided.
NAT updates use separate tables, and iptables guard jumps precede external jumps.
Neither backend changes the global OUTPUT policy or flushes unrelated rules.

## Contributing & security

Contributions welcome under the licenses above. Please report security issues
privately — see [`SECURITY.md`](SECURITY.md).

---

fluxpeer is part of the **openprx** family. Status: actively developed; interfaces may
change before a tagged 1.0.
