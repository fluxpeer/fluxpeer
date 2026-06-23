//! SQL persistence for coordination entities.
//!
//! Uses sqlx's `Any` driver so the **same code runs on PostgreSQL in production**
//! (`postgres://…`, the decision) and is verified here against an in-memory
//! SQLite database (real driver, portable ANSI SQL, no external infra needed).
//! The live in-memory [`crate::state::Store`] is swapped for this once wired.

use crate::domain::{AuditEntry, Device, DeviceStatus, Invite, Network, RelayNode, Route};
use sqlx::any::AnyPoolOptions;
use sqlx::{AnyPool, Row};

/// Connect to a database by URL (e.g. `postgres://…` or `sqlite::memory:`).
pub async fn connect(url: &str) -> Result<AnyPool, sqlx::Error> {
    sqlx::any::install_default_drivers();
    AnyPoolOptions::new().connect(url).await
}

/// Create the schema if absent (portable across SQLite + PostgreSQL).
pub async fn migrate(pool: &AnyPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS network (\
            id TEXT PRIMARY KEY, name TEXT NOT NULL, ipv4_pool TEXT NOT NULL, \
            ipv6_ula TEXT NOT NULL, config_epoch BIGINT NOT NULL)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS invite (\
            code TEXT PRIMARY KEY, network_id TEXT NOT NULL, expires_at BIGINT, \
            max_uses BIGINT, uses BIGINT NOT NULL)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS device (\
            id TEXT PRIMARY KEY, network_id TEXT NOT NULL, name TEXT NOT NULL, \
            wg_public_key TEXT NOT NULL, address_v4 TEXT, address_v6 TEXT, status TEXT NOT NULL, \
            endpoints TEXT)",
    )
    .execute(pool)
    .await?;
    // Best-effort column add for DBs created before `endpoints` existed; ignore
    // the "duplicate column" error when it's already present (portable across
    // SQLite/PostgreSQL, which lack a common ADD COLUMN IF NOT EXISTS).
    let _ = sqlx::query("ALTER TABLE device ADD COLUMN endpoints TEXT")
        .execute(pool)
        .await;
    // Editable wg settings (JSON: mtu / dns / endpoint override) — wg-quick-ish
    // knobs the node applies. Best-effort add for pre-existing DBs.
    let _ = sqlx::query("ALTER TABLE device ADD COLUMN settings TEXT").execute(pool).await;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS relay (\
            id TEXT PRIMARY KEY, region TEXT NOT NULL, url TEXT NOT NULL, \
            network_id TEXT, anytls BIGINT NOT NULL DEFAULT 0, stun_url TEXT)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS admin (\
            username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, created_at BIGINT NOT NULL)",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS audit (ts BIGINT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL)")
        .execute(pool)
        .await?;
    // Per-device traffic stats (node-reported cumulative rx/tx + a per-peer JSON
    // blob), updated every poll. Separate table to isolate the high-churn writes.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS device_stats (\
            device_id TEXT PRIMARY KEY, rx_bytes BIGINT NOT NULL, tx_bytes BIGINT NOT NULL, \
            peers TEXT, updated_at BIGINT NOT NULL)",
    )
    .execute(pool)
    .await?;
    // Subnet routes: a device advertises a LAN prefix; effective once approved.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS route (\
            id TEXT PRIMARY KEY, network_id TEXT NOT NULL, device_id TEXT NOT NULL, \
            prefix TEXT NOT NULL, approved BIGINT NOT NULL DEFAULT 0)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

fn row_to_route(r: &sqlx::any::AnyRow) -> Route {
    Route {
        id: r.get::<String, _>("id"),
        network_id: r.get::<String, _>("network_id"),
        device_id: r.get::<String, _>("device_id"),
        prefix: r.get::<String, _>("prefix"),
        approved: r.get::<i64, _>("approved") != 0,
    }
}

pub async fn insert_route(pool: &AnyPool, r: &Route) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO route (id, network_id, device_id, prefix, approved) VALUES ($1,$2,$3,$4,$5)")
        .bind(&r.id)
        .bind(&r.network_id)
        .bind(&r.device_id)
        .bind(&r.prefix)
        .bind(i64::from(r.approved))
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_route(pool: &AnyPool, id: &str) -> Result<Option<Route>, sqlx::Error> {
    Ok(sqlx::query("SELECT id, network_id, device_id, prefix, approved FROM route WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .map(|r| row_to_route(&r)))
}

pub async fn list_routes_for_device(pool: &AnyPool, device_id: &str) -> Result<Vec<Route>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, network_id, device_id, prefix, approved FROM route WHERE device_id = $1")
        .bind(device_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_route).collect())
}

/// Approved `(device_id, prefix)` routes for a network — merged into peer allowed-ips.
pub async fn approved_routes_for_network(pool: &AnyPool, network_id: &str) -> Result<Vec<(String, String)>, sqlx::Error> {
    let rows = sqlx::query("SELECT device_id, prefix FROM route WHERE network_id = $1 AND approved <> 0")
        .bind(network_id)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.get::<String, _>("device_id"), r.get::<String, _>("prefix")))
        .collect())
}

pub async fn set_route_approved(pool: &AnyPool, id: &str, approved: bool) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE route SET approved = $1 WHERE id = $2")
        .bind(i64::from(approved))
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_route(pool: &AnyPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM route WHERE id = $1").bind(id).execute(pool).await?;
    Ok(())
}

/// Upsert a device's latest cumulative traffic stats.
pub async fn upsert_device_stats(
    pool: &AnyPool,
    device_id: &str,
    rx: i64,
    tx: i64,
    peers_json: &str,
    at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO device_stats (device_id, rx_bytes, tx_bytes, peers, updated_at) VALUES ($1,$2,$3,$4,$5) \
         ON CONFLICT(device_id) DO UPDATE SET rx_bytes=$2, tx_bytes=$3, peers=$4, updated_at=$5",
    )
    .bind(device_id)
    .bind(rx)
    .bind(tx)
    .bind(peers_json)
    .bind(at)
    .execute(pool)
    .await?;
    Ok(())
}

/// A device's latest stats: `(rx, tx, peers_json, updated_at)` if reported.
pub async fn get_device_stats(pool: &AnyPool, device_id: &str) -> Result<Option<(i64, i64, String, i64)>, sqlx::Error> {
    let row = sqlx::query("SELECT rx_bytes, tx_bytes, peers, updated_at FROM device_stats WHERE device_id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| {
        (
            r.get::<i64, _>("rx_bytes"),
            r.get::<i64, _>("tx_bytes"),
            r.get::<Option<String>, _>("peers").unwrap_or_default(),
            r.get::<i64, _>("updated_at"),
        )
    }))
}

/// Per-device `(device_id, rx, tx, updated_at)` for every device in a network with
/// reported stats (the admin table rollup).
pub async fn list_network_stats(pool: &AnyPool, network_id: &str) -> Result<Vec<(String, i64, i64, i64)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT s.device_id, s.rx_bytes, s.tx_bytes, s.updated_at FROM device_stats s \
         JOIN device d ON d.id = s.device_id WHERE d.network_id = $1",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<String, _>("device_id"),
                r.get::<i64, _>("rx_bytes"),
                r.get::<i64, _>("tx_bytes"),
                r.get::<i64, _>("updated_at"),
            )
        })
        .collect())
}

/// Insert a relay into the directory.
pub async fn insert_relay(pool: &AnyPool, r: &RelayNode) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO relay (id, region, url, network_id, anytls, stun_url) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(&r.id)
        .bind(&r.region)
        .bind(&r.url)
        .bind(&r.network_id)
        .bind(i64::from(r.anytls))
        .bind(&r.stun_url)
        .execute(pool)
        .await?;
    Ok(())
}

/// Relays usable by a network: those scoped to it plus shared/official ones
/// (`network_id IS NULL`).
pub async fn list_relays(pool: &AnyPool, network_id: &str) -> Result<Vec<RelayNode>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, region, url, network_id, anytls, stun_url FROM relay WHERE network_id = $1 OR network_id IS NULL",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RelayNode {
            id: r.get::<String, _>("id"),
            region: r.get::<String, _>("region"),
            url: r.get::<String, _>("url"),
            network_id: r.get::<Option<String>, _>("network_id"),
            anytls: r.get::<i64, _>("anytls") != 0,
            stun_url: r.get::<Option<String>, _>("stun_url"),
        })
        .collect())
}

/// Replace a device's reported candidate endpoints (comma-separated `ip:port`s).
pub async fn set_device_endpoints(pool: &AnyPool, id: &str, endpoints: &[String]) -> Result<(), sqlx::Error> {
    let csv = endpoints.join(",");
    sqlx::query("UPDATE device SET endpoints = $1 WHERE id = $2")
        .bind(csv)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A device's reported candidate endpoints (empty if none/unset).
pub async fn get_device_endpoints(pool: &AnyPool, id: &str) -> Result<Vec<String>, sqlx::Error> {
    let row = sqlx::query("SELECT endpoints FROM device WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row
        .and_then(|r| r.get::<Option<String>, _>("endpoints"))
        .map(|s| s.split(',').filter(|x| !x.is_empty()).map(String::from).collect())
        .unwrap_or_default())
}

pub async fn insert_network(pool: &AnyPool, n: &Network) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO network (id, name, ipv4_pool, ipv6_ula, config_epoch) VALUES ($1,$2,$3,$4,$5)")
        .bind(&n.id)
        .bind(&n.name)
        .bind(&n.ipv4_pool)
        .bind(&n.ipv6_ula)
        .bind(n.config_epoch as i64)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_network(pool: &AnyPool, id: &str) -> Result<Option<Network>, sqlx::Error> {
    let row = sqlx::query("SELECT id, name, ipv4_pool, ipv6_ula, config_epoch FROM network WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| Network {
        id: r.get::<String, _>("id"),
        name: r.get::<String, _>("name"),
        ipv4_pool: r.get::<String, _>("ipv4_pool"),
        ipv6_ula: r.get::<String, _>("ipv6_ula"),
        config_epoch: r.get::<i64, _>("config_epoch") as u64,
    }))
}

pub async fn bump_network_epoch(pool: &AnyPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE network SET config_epoch = config_epoch + 1 WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_invite(pool: &AnyPool, inv: &Invite) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO invite (code, network_id, expires_at, max_uses, uses) VALUES ($1,$2,$3,$4,$5)")
        .bind(&inv.code)
        .bind(&inv.network_id)
        .bind(inv.expires_at)
        .bind(inv.max_uses.map(|m| m as i64))
        .bind(inv.uses as i64)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_invite(pool: &AnyPool, code: &str) -> Result<Option<Invite>, sqlx::Error> {
    let row = sqlx::query("SELECT code, network_id, expires_at, max_uses, uses FROM invite WHERE code = $1")
        .bind(code)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| Invite {
        code: r.get::<String, _>("code"),
        network_id: r.get::<String, _>("network_id"),
        expires_at: r.get::<Option<i64>, _>("expires_at"),
        max_uses: r.get::<Option<i64>, _>("max_uses").map(|m| m as u32),
        uses: r.get::<i64, _>("uses") as u32,
    }))
}

pub async fn list_invites(pool: &AnyPool, network_id: &str) -> Result<Vec<Invite>, sqlx::Error> {
    let rows = sqlx::query("SELECT code, network_id, expires_at, max_uses, uses FROM invite WHERE network_id = $1")
        .bind(network_id)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| Invite {
            code: r.get::<String, _>("code"),
            network_id: r.get::<String, _>("network_id"),
            expires_at: r.get::<Option<i64>, _>("expires_at"),
            max_uses: r.get::<Option<i64>, _>("max_uses").map(|m| m as u32),
            uses: r.get::<i64, _>("uses") as u32,
        })
        .collect())
}

pub async fn insert_device(pool: &AnyPool, d: &Device) -> Result<(), sqlx::Error> {
    let status = match d.status {
        DeviceStatus::Active => "active",
        DeviceStatus::Revoked => "revoked",
    };
    sqlx::query(
        "INSERT INTO device (id, network_id, name, wg_public_key, address_v4, address_v6, status) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(&d.id)
    .bind(&d.network_id)
    .bind(&d.name)
    .bind(&d.wg_public_key)
    .bind(&d.address_v4)
    .bind(&d.address_v6)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_devices(pool: &AnyPool, network_id: &str) -> Result<Vec<Device>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, network_id, name, wg_public_key, address_v4, address_v6, status \
         FROM device WHERE network_id = $1 ORDER BY id",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| Device {
            id: r.get::<String, _>("id"),
            network_id: r.get::<String, _>("network_id"),
            name: r.get::<String, _>("name"),
            wg_public_key: r.get::<String, _>("wg_public_key"),
            address_v4: r.get::<Option<String>, _>("address_v4"),
            address_v6: r.get::<Option<String>, _>("address_v6"),
            status: if r.get::<String, _>("status") == "revoked" {
                DeviceStatus::Revoked
            } else {
                DeviceStatus::Active
            },
        })
        .collect())
}

pub async fn list_networks(pool: &AnyPool) -> Result<Vec<Network>, sqlx::Error> {
    let rows = sqlx::query("SELECT id, name, ipv4_pool, ipv6_ula, config_epoch FROM network ORDER BY id")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| Network {
            id: r.get::<String, _>("id"),
            name: r.get::<String, _>("name"),
            ipv4_pool: r.get::<String, _>("ipv4_pool"),
            ipv6_ula: r.get::<String, _>("ipv6_ula"),
            config_epoch: r.get::<i64, _>("config_epoch") as u64,
        })
        .collect())
}

pub async fn get_device(pool: &AnyPool, id: &str) -> Result<Option<Device>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, network_id, name, wg_public_key, address_v4, address_v6, status FROM device WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| Device {
        id: r.get::<String, _>("id"),
        network_id: r.get::<String, _>("network_id"),
        name: r.get::<String, _>("name"),
        wg_public_key: r.get::<String, _>("wg_public_key"),
        address_v4: r.get::<Option<String>, _>("address_v4"),
        address_v6: r.get::<Option<String>, _>("address_v6"),
        status: if r.get::<String, _>("status") == "revoked" {
            DeviceStatus::Revoked
        } else {
            DeviceStatus::Active
        },
    }))
}

pub async fn incr_invite_uses(pool: &AnyPool, code: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE invite SET uses = uses + 1 WHERE code = $1")
        .bind(code)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn set_device_status(pool: &AnyPool, id: &str, status: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE device SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Store a device's editable wg settings (raw JSON blob: {mtu, dns, endpoint}).
pub async fn set_device_settings(pool: &AnyPool, id: &str, settings_json: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE device SET settings = $1 WHERE id = $2")
        .bind(settings_json)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A device's editable wg settings JSON (empty `{}` if unset).
pub async fn get_device_settings(pool: &AnyPool, id: &str) -> Result<String, sqlx::Error> {
    let row = sqlx::query("SELECT settings FROM device WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row
        .and_then(|r| r.get::<Option<String>, _>("settings"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "{}".to_string()))
}

pub async fn set_device_name(pool: &AnyPool, id: &str, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE device SET name = $1 WHERE id = $2")
        .bind(name)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// IPv4 addresses currently held by ACTIVE devices in a network (for allocation).
pub async fn active_device_v4s(pool: &AnyPool, network_id: &str) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT address_v4 FROM device WHERE network_id = $1 AND status = 'active' AND address_v4 IS NOT NULL",
    )
    .bind(network_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("address_v4")).collect())
}

/// Total rows across entity tables (used to seed monotonic id generation).
pub async fn count_rows(pool: &AnyPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT (SELECT COUNT(*) FROM network) + (SELECT COUNT(*) FROM invite) + (SELECT COUNT(*) FROM device) AS n",
    )
    .fetch_one(pool)
    .await?;
    Ok(row.get::<i64, _>("n"))
}

#[cfg(test)]
mod test {
    use super::*;

    async fn mem_pool() -> AnyPool {
        sqlx::any::install_default_drivers();
        // max_connections(1): each :memory: connection is a distinct DB.
        AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn schema_and_crud_roundtrip() {
        let pool = mem_pool().await;
        migrate(&pool).await.unwrap();

        let net = Network {
            id: "net-1".into(),
            name: "home".into(),
            ipv4_pool: "100.72.16.0/24".into(),
            ipv6_ula: "fd72:15ab:0000::/48".into(),
            config_epoch: 0,
        };
        insert_network(&pool, &net).await.unwrap();
        assert_eq!(get_network(&pool, "net-1").await.unwrap().unwrap().name, "home");

        bump_network_epoch(&pool, "net-1").await.unwrap();
        assert_eq!(get_network(&pool, "net-1").await.unwrap().unwrap().config_epoch, 1);

        let inv = Invite {
            code: "inv-1".into(),
            network_id: "net-1".into(),
            expires_at: None,
            max_uses: Some(5),
            uses: 0,
        };
        insert_invite(&pool, &inv).await.unwrap();
        let got = get_invite(&pool, "inv-1").await.unwrap().unwrap();
        assert_eq!(got.max_uses, Some(5));
        assert_eq!(got.expires_at, None);

        let dev = Device {
            id: "dev-1".into(),
            network_id: "net-1".into(),
            name: "laptop".into(),
            wg_public_key: "pk-A".into(),
            address_v4: Some("100.72.16.100".into()),
            address_v6: Some("fd72:15ab:0:1::64".into()),
            status: DeviceStatus::Active,
        };
        insert_device(&pool, &dev).await.unwrap();
        let devs = list_devices(&pool, "net-1").await.unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0], dev);
    }

    #[tokio::test]
    async fn missing_rows_are_none_and_empty() {
        let pool = mem_pool().await;
        migrate(&pool).await.unwrap();
        assert!(get_network(&pool, "nope").await.unwrap().is_none());
        assert!(get_invite(&pool, "nope").await.unwrap().is_none());
        assert!(list_devices(&pool, "nope").await.unwrap().is_empty());
    }
}

// ── admin accounts ──────────────────────────────────────────────────────────

pub async fn count_admins(pool: &AnyPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("SELECT COUNT(*) AS c FROM admin").fetch_one(pool).await?;
    Ok(row.get::<i64, _>("c"))
}

pub async fn admin_hash(pool: &AnyPool, username: &str) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query("SELECT password_hash FROM admin WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.get::<String, _>("password_hash")))
}

pub async fn create_admin(pool: &AnyPool, username: &str, hash: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO admin (username, password_hash, created_at) VALUES ($1,$2,$3)")
        .bind(username)
        .bind(hash)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn update_admin_password(pool: &AnyPool, username: &str, hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE admin SET password_hash = $1 WHERE username = $2")
        .bind(hash)
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_admins(pool: &AnyPool) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query("SELECT username FROM admin ORDER BY username")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn delete_admin(pool: &AnyPool, username: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM admin WHERE username = $1")
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_audit(pool: &AnyPool, ts: i64, actor: &str, action: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit (ts, actor, action) VALUES ($1,$2,$3)")
        .bind(ts)
        .bind(actor)
        .bind(action)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_audit(pool: &AnyPool, limit: i64) -> Result<Vec<AuditEntry>, sqlx::Error> {
    let rows = sqlx::query("SELECT ts, actor, action FROM audit ORDER BY ts DESC LIMIT $1")
        .bind(limit)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| AuditEntry {
            ts: r.get::<i64, _>("ts"),
            actor: r.get::<String, _>("actor"),
            action: r.get::<String, _>("action"),
        })
        .collect())
}
