// SPDX-License-Identifier: BSD-3-Clause
//! Transactional migration and durable IDs shared by all control store writers.

use std::collections::{HashMap, HashSet};
use sqlx::{Any, AnyConnection, AnyPool, Row, Transaction};

/// Obtain the database write lock before any enrollment/IPAM read. This is a
/// row lock on PostgreSQL and a writer reservation on SQLite. It also serializes
/// imports and ID allocation across distinct stores/processes, not just tasks.
pub(crate) async fn begin(pool: &AnyPool) -> Result<Transaction<'_, Any>, sqlx::Error> {
    // The first statement is a write, with no preceding SELECT/snapshot:
    // SQLite reserves the writer here just as BEGIN IMMEDIATE would, so it
    // waits via busy_timeout instead of attempting a read-to-write upgrade.
    // PostgreSQL retains its existing row-level lock semantics.
    let mut tx = pool.begin().await?;
    let locked = sqlx::query("UPDATE control_sequence SET value = value WHERE name = 'entity'")
        .execute(&mut *tx).await?.rows_affected();
    if locked != 1 { return Err(sqlx::Error::Protocol("entity ID sequence missing".into())); }
    Ok(tx)
}

pub(crate) async fn next(conn: &mut AnyConnection) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("UPDATE control_sequence SET value = value + 1 WHERE name = 'entity' AND value < 9223372036854775807 RETURNING value")
        .fetch_optional(conn).await?
        .ok_or_else(|| sqlx::Error::Protocol("entity ID sequence exhausted or missing".into()))?;
    row.try_get("value")
}

pub(crate) async fn migrate(pool: &AnyPool) -> Result<(), sqlx::Error> {
    sqlx::query("CREATE TABLE IF NOT EXISTS control_sequence (name TEXT PRIMARY KEY, value BIGINT NOT NULL)")
        .execute(pool).await?;
    sqlx::query("INSERT INTO control_sequence (name, value) VALUES ('entity', 0) ON CONFLICT(name) DO NOTHING")
        .execute(pool).await?;
    let mut tx = begin(pool).await?;
    // Recover the actual maximum numeric suffix, including relays and routes.
    // The durable high-water mark never falls after deletions or restarts.
    let ids = sqlx::query("SELECT id FROM network UNION ALL SELECT id FROM device UNION ALL SELECT id FROM relay UNION ALL SELECT id FROM route")
        .fetch_all(&mut *tx).await?;
    let mut max_id = 0;
    for row in ids {
        let id: String = row.try_get("id")?;
        if let Some((prefix, suffix)) = id.rsplit_once('-')
            && ["net", "dev", "relay", "route"].contains(&prefix)
            && !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
        {
            let value = suffix.parse::<i64>().map_err(|_| sqlx::Error::Protocol(format!("invalid entity ID: {id}")))?;
            max_id = max_id.max(value);
        }
    }
    sqlx::query("UPDATE control_sequence SET value = $1 WHERE name = 'entity' AND value < $1")
        .bind(max_id).execute(&mut *tx).await?;

    let rows = sqlx::query("SELECT id, network_id, wg_public_key, address_v4, address_v6, auth_token, status FROM device ORDER BY id")
        .fetch_all(&mut *tx).await?;
    let mut keys = HashMap::new();
    let mut addresses = HashMap::new();
    let mut normalized = Vec::new();
    let mut changed_networks = HashSet::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let network: String = row.try_get("network_id")?;
        let old: String = row.try_get("wg_public_key")?;
        let status: String = row.try_get("status")?;
        let active = match status.as_str() {
            "active" => true,
            "revoked" => false,
            _ => return Err(sqlx::Error::Protocol(format!("unknown status {status:?} on device {id} in network {network}"))),
        };
        let key = if active {
            fluxpeer_sdk::key::normalize(&old).ok_or_else(|| sqlx::Error::Protocol(format!(
                "invalid public key on active device {id} in network {network}; repair legacy data before migration")))?
        } else {
            // Tombstones are historical evidence, not current peer identities.
            fluxpeer_sdk::key::normalize(&old).unwrap_or_else(|| old.clone())
        };
        if active && let Some(other) = keys.insert((network.clone(), key.clone()), id.clone()) {
            return Err(sqlx::Error::Protocol(format!("duplicate public key on active devices {other} and {id} in network {network}")));
        }
        let old_address: Option<String> = row.try_get("address_v4")?;
        let old_v6: Option<String> = row.try_get("address_v6")?;
        let old_token: Option<String> = row.try_get("auth_token")?;
        let address = if !active { None } else {
            old_address.as_deref().map(|s| s.parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.to_string()).map_err(|_| sqlx::Error::Protocol(format!("invalid IPv4 on active device {id} in network {network}"))))
                .transpose()?
        };
        if active && let Some(address) = &address
            && let Some(other) = addresses.insert((network.clone(), address.clone()), id.clone())
        {
            return Err(sqlx::Error::Protocol(format!("duplicate IPv4 on active devices {other} and {id} in network {network}")));
        }
        let v6 = if active { old_v6.clone() } else { None };
        let token = if active { old_token.clone() } else { None };
        if key != old || address != old_address || v6 != old_v6 || token != old_token {
            if active { changed_networks.insert(network); }
            normalized.push((id, key, address, v6, token));
        }
    }
    // Replace the earlier unconditional indexes in the same transaction. This
    // permits normalization of a revoked alias alongside an active identity.
    sqlx::query("DROP INDEX IF EXISTS device_network_key").execute(&mut *tx).await?;
    sqlx::query("DROP INDEX IF EXISTS device_network_v4").execute(&mut *tx).await?;
    for (id, key, address, v6, token) in normalized {
        sqlx::query("UPDATE device SET wg_public_key = $1, address_v4 = $2, address_v6 = $3, auth_token = $4 WHERE id = $5")
            .bind(key).bind(address).bind(v6).bind(token).bind(id).execute(&mut *tx).await?;
    }
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS device_network_active_key ON device (network_id, wg_public_key) WHERE status = 'active'")
        .execute(&mut *tx).await?;
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS device_network_active_v4 ON device (network_id, address_v4) WHERE status = 'active'")
        .execute(&mut *tx).await?;
    for network in changed_networks {
        super::persistence::bump_network_epoch(&mut *tx, &network).await?;
    }
    tx.commit().await
}

/// Retry the whole transaction, never just the failed statement/snapshot.
pub(crate) fn retryable(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|e| {
        matches!(e.code().as_deref(), Some("40001" | "40P01" | "5" | "6" | "261" | "262" | "517"))
    })
}
