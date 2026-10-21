# control-server

Open coordination plane: network / device / invite / peer / route / relay-directory. Reuses Axum+SeaORM+PG18 patterns; no billing.

Coordination plane: networks/devices/invites/peers/routes/IPAM + `/api/v1`.

## Device integrity and upgrades (T-0029)

Enrollment, proof-of-possession challenges and imports accept 32-byte public keys
as hex (either case) or padded WireGuard base64. Storage and configuration responses
use lowercase hex. Invalid keys are rejected; nodes isolate invalid peers from an
older server without panicking. The SDK import builder also normalizes keys.

New enrollment consumes an invite with an atomic `uses < max_uses` conditional
update. Invite consumption, address allocation, device/token insertion, ID allocation
and the network epoch commit in one transaction. A durable `control_sequence` row
serializes these operations and imports across store instances (PostgreSQL row lock,
SQLite writer lock). Transient busy/deadlock/serialization failures retry the entire
transaction with bounded backoff. Notifications follow commit.

Re-enrollment of the same canonical key in the same network returns the existing
active device and rotates its token. Name, address and routes are preserved. It
requires an existing, unexpired invite for that network and HTTP proof of possession;
an already consumed invite can rotate an existing identity without admitting a new
one. This does not consume another invite use or change the config epoch. Only the
latest returned token remains valid. Existing WS watches revalidate their token
before every push and close if it has rotated. Watches opened with the administrator
master key instead revalidate that master key before each push; device-token
rotation does not disconnect them. Re-import skips active canonical keys.

Revocation invalidates the old token and preserves the old row as a tombstone. It
does not permanently ban that public key: with a new valid invitation and PoP, the
same key can enroll a **new** device, consuming one invite use and allocating a new
ID, token and address lease. Released addresses can be recycled by IPAM. The new
record does not inherit the old record's approved routes or settings. Active-key
re-entry remains idempotent, even if historical revoked rows share the key.

Startup migration normalizes legacy keys and creates partial unique indexes on
`(network_id, wg_public_key)` and `(network_id, address_v4)` **WHERE status = 'active'**.
It replaces the earlier unconditional indexes in the same transaction. Revoked
rows may contain duplicate or invalid keys; invalid revoked keys retain their exact
original text. Tombstones release addresses and tokens. Only rows that actually
change are updated. Active records retain their identity, routes, settings and
credentials. Multiple NULL addresses remain legal. Imports validate IPv4 addresses.

Before upgrading, stop control writers and back up the database. Invalid active
keys, duplicate canonical active keys (including hex/base64 aliases), or duplicate
active IPv4 addresses fail migration with the network and affected device IDs.
Only the exact status values `active` and `revoked` are accepted at migration;
unknown statuses reject startup with the device ID and network. Reads treat only
`active` as active, failing closed for any unexpected value.
The integrity migration rolls back without choosing an identity to merge/delete.
Inspect those IDs and choose the record to retire explicitly. The following repair
scripts revoke a chosen conflicting record, remove its routes and invalidate its
token; then restart to retry migration. Replace only the example network/device IDs
with the IDs from the diagnostic. Run against the backed-up maintenance database.

SQLite (`sqlite3 control.db`; `.bail on` stops execution on any error):

```sql
.bail on
BEGIN IMMEDIATE;
CREATE TEMP TABLE repair_targets (network_id TEXT, device_id TEXT);
INSERT INTO repair_targets VALUES ('net-1', 'dev-101');
UPDATE network SET config_epoch = config_epoch + 1
 WHERE id IN (SELECT network_id FROM repair_targets);
DELETE FROM route WHERE device_id IN (
 SELECT d.id FROM device d JOIN repair_targets t
 ON d.id = t.device_id AND d.network_id = t.network_id);
UPDATE device SET status = 'revoked', auth_token = NULL,
 address_v4 = NULL, address_v6 = NULL
 WHERE EXISTS (SELECT 1 FROM repair_targets t
 WHERE t.device_id = device.id AND t.network_id = device.network_id);
-- Optional permanent deletion, instead of retaining the revoked tombstone:
-- DELETE FROM device_stats WHERE device_id IN (SELECT d.id FROM device d JOIN repair_targets t ON d.id = t.device_id AND d.network_id = t.network_id);
-- DELETE FROM device WHERE EXISTS (SELECT 1 FROM repair_targets t WHERE t.device_id = device.id AND t.network_id = device.network_id);
DROP TABLE repair_targets;
COMMIT;
```

PostgreSQL (`psql`; `ON_ERROR_STOP` aborts the script on error):

```sql
\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE repair_targets (network_id TEXT, device_id TEXT) ON COMMIT DROP;
INSERT INTO repair_targets VALUES ('net-1', 'dev-101');
UPDATE network SET config_epoch = config_epoch + 1
 WHERE id IN (SELECT network_id FROM repair_targets);
DELETE FROM route USING device d, repair_targets t
 WHERE route.device_id = d.id AND d.id = t.device_id AND d.network_id = t.network_id;
UPDATE device d SET status = 'revoked', auth_token = NULL,
 address_v4 = NULL, address_v6 = NULL
 FROM repair_targets t WHERE d.id = t.device_id AND d.network_id = t.network_id;
-- Optional permanent deletion, instead of retaining the revoked tombstone:
-- DELETE FROM device_stats s USING device d, repair_targets t WHERE s.device_id = d.id AND d.id = t.device_id AND d.network_id = t.network_id;
-- DELETE FROM device d USING repair_targets t WHERE d.id = t.device_id AND d.network_id = t.network_id;
COMMIT;
```

Uncomment both optional DELETE statements only when permanent removal is intended;
route removal and token invalidation are already included in either mode. A revoked
malformed/duplicate key does not need to be repaired merely to start the server.

The persistent ID high-water mark is seeded from numeric IDs in network, device,
relay and route tables, then incremented in the database. Deletions and restarts do
not lower it. Existing nonnumeric IDs are retained. Network counts only influence
pool spread, never IDs.
