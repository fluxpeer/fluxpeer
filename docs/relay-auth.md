<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Relay authentication, protocol version 2

The relay uses a persisted random X25519 identity. By default it loads
`$FLUXPEER_DATA_DIR/relay.key`, or `/var/lib/fluxpeer/relay.key` when the data
directory is unset. `FLUXPEER_RELAY_KEY_FILE` overrides this path. Missing parent
directories are created with mode 0700 on Unix; existing directories retain their
permissions. On first startup the relay creates 32 random raw bytes with exclusive
creation and mode 0600; subsequent starts reuse the same key. Startup rejects
malformed files, symlinks and Unix files accessible by group or others. Back up the
key; changing it requires updating the public key in the directory and client pins.
Only the public key is logged at startup.

Run `fluxpeer relay public-key` to print the hex public key without starting any
listener. This creates the identity if absent and uses the same path resolution
and safety checks as server startup. `--key-file PATH` overrides both environment
variables for this command. Use the same path/environment as the running relay.

Register that public key using `fp --server CONTROL relay add REGION ENDPOINT
--public-key KEY` (or `fluxpeer ctl --server CONTROL relay add ...`), with the
existing `--anytls`, `--node-id`, `--stun-url`, `--network-id` options as appropriate.
The registration/update API accepts `public_key` as 32-byte hex or base64.
SQLite/PostgreSQL migration adds a nullable `public_key` column. Old rows remain
readable, but cannot provide relay connectivity until their key is set. To update an existing row, use the authenticated
`PUT /api/v1/relays/{id}` API with its region, URL, scope and transport fields plus
the new `public_key`; `relay add` creates a new row. The public `node_id` still selects
the AnyTLS camouflage password; it is never used as the relay private key or as
proof of client identity.

A node normally obtains the pin from the authenticated control directory. An
explicit `relay` endpoint uses `relay_public_key`, or the key of a matching directory
endpoint if the local pin is absent. A malformed explicit pin does not fall back.
No usable key means no relay target; automatic mode can continue using direct
paths, while forced relay mode waits for a usable directory entry. There is no
legacy wire fallback. Relay and bond protocol versions are both 2; version 1 is
rejected with a version diagnostic.

For existing deployments, schedule the relay connectivity interruption and upgrade
in this order:

1. Upgrade the relay, preserving its identity volume (or configure a persistent key
   path before first version-2 startup).
2. Read `fluxpeer relay public-key` in that relay's environment, then register its
   public key in a control server that supports the `public_key` field. Update any
   explicit `relay_public_key` node pins too.
3. Upgrade the nodes to version 2. Version-1 nodes are rejected by the upgraded relay
   during the transition; there is no mixed-version relay compatibility.

See [deployment examples](../deploy/README.md) for persistent volumes and commands.

## Authentication boundary

`fp_transport::link::LinkAuthenticator` is optional for direct WG users of
TCP-bond/AnyTLS. Those users retain their concurrent connection establishment;
WG authenticates carried packets. Relay listeners and dialers always install the
hook and require its verified session identity before registering `ClientInfo`.
The separate public transport-password/TLS wrapper is not that identity proof.

The version-2 bond header is `version:u8 || bond_id:16 || total:u8 || index:u32be ||
authenticated:u8`. Link zero performs relay authentication before yamux begins.
It sends `version:u32be || client_pub:32`, receives a fresh 32-byte challenge, and
returns `HMAC-BLAKE2s(DH, "fluxpeer-relay-auth-v1" || challenge || client_pub)`.
Both sides reject non-contributory X25519 DH and derive
`link_key = HMAC-BLAKE2s(DH, "fluxpeer-relay-link-v1" || bond_id || challenge)`.
Plain TCP uses the same authentication exchange with a zero bond ID.

The node currently reuses its WireGuard static X25519 key as the client identity
for relay DH. The relay authentication, link derivation and confirmation labels
above separate these HMAC operations from WireGuard's key schedule and from each
other. This is intentional key reuse, not a separate client relay key; rotating
the node's WG identity also changes its relay identity.

Every secondary and reconnect link must answer a fresh relay nonce with
`HMAC-BLAKE2s(link_key, nonce || bond_id || index:u32be)`. A group that is absent,
pending authentication or revoked rejects secondary links immediately. Bad
proofs are counted and logged. Only successful proofs reach yamux/group joining.
The relay returns a domain-separated key confirmation MAC over
`"fluxpeer-relay-confirm-v1" || bond_id || index:u32be || nonce`; primary/plain
confirmation uses a zero nonce because their freshly derived key already binds
the primary challenge. Clients verify this confirmation against their pin.

The session identity must match `ClientInfo`. Hub replacement revokes the previous
group key, and frames from its previous channel cannot route. Disconnect, task
cancellation and bond sender closure also invalidate the key. Authentication
establishes key possession; it does not introduce network-membership authorization
or change WG payload encryption. Plain TCP itself remains unencrypted.

## Disco probes

Each peer keeps at most 128 seen Pings and 128 pending probes. Seen IDs remain
until their timestamp is outside the existing ±30-second MAC window, including
future clock skew; a full cache refuses new entries instead of evicting live ones.
A Pong must match an unexpired local probe and one of its destination addresses,
and is consumed once. The dispatcher routes roaming Pongs by pending tx_id.
A new source's authenticated Ping triggers a return-path challenge and never
changes `direct_addr` by itself. Authenticated WG data retains its roaming behavior.

The local regression suite uses loopback sockets and duplex streams. Live
PostgreSQL migration, deployed relay upgrade, NAT roaming, and cross-host traffic
require separate QA. The optional remote relay test also requires
`RELAY_TEST_PUBLIC_KEY` (hex) when `RELAY_TEST_ADDR` is supplied.
