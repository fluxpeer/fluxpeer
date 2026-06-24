//! Persistent coordination store backed by SQL (sqlx `Any`).
//!
//! Same coordination logic as [`crate::state::Store`] but durable: networks,
//! invites, devices live in the DB, and IP allocation is **derived from the
//! current active-device set** (so it survives restarts and respects recycling).
//! Verified end-to-end on in-memory SQLite; production points it at PostgreSQL.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use sqlx::AnyPool;
use tokio::sync::watch;

use crate::domain::{Device, DeviceConfig, DeviceStatus, ImportDevice, ImportResult, Invite, Network, PeerConfig, RelayNode, Route};
use crate::ipam::{DEVICE_HOST_MAX, DEVICE_HOST_MIN};
use crate::persistence as db;

#[derive(Debug, thiserror::Error)]
pub enum SqlStoreError {
    #[error("network not found")]
    NetworkNotFound,
    #[error("device not found")]
    DeviceNotFound,
    #[error("route not found")]
    RouteNotFound,
    #[error("invalid invite")]
    InvalidInvite,
    #[error("address pool exhausted")]
    PoolExhausted,
    #[error("bad network pool config: {0}")]
    BadPool(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

type Result<T> = std::result::Result<T, SqlStoreError>;

pub struct SqlStore {
    pool: AnyPool,
    seq: AtomicU64,
    net_index: AtomicU64,
    /// Per-network config-epoch broadcaster for WS push (ephemeral, in-process).
    epoch_tx: Mutex<HashMap<String, watch::Sender<u64>>>,
}

impl SqlStore {
    /// Connect, migrate, and seed id generation from existing rows.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = db::connect(url).await?;
        db::migrate(&pool).await?;
        let seed = db::count_rows(&pool).await? as u64 + 1;
        let nets = db::count_rows(&pool).await?; // coarse; net_index only affects pool spread
        Ok(Self {
            pool,
            seq: AtomicU64::new(seed),
            net_index: AtomicU64::new(nets.max(0) as u64),
            epoch_tx: Mutex::new(HashMap::new()),
        })
    }

    /// Bump a network's epoch in the DB and notify any WS watchers.
    async fn bump_and_notify(&self, network_id: &str) -> Result<()> {
        db::bump_network_epoch(&self.pool, network_id).await?;
        if let Some(net) = db::get_network(&self.pool, network_id).await?
            && let Some(tx) = self.epoch_tx.lock().get(network_id)
        {
            let _ = tx.send(net.config_epoch);
        }
        Ok(())
    }

    /// Subscribe to a network's epoch changes (create-if-missing for reconnects).
    pub fn subscribe(&self, network_id: &str) -> watch::Receiver<u64> {
        let mut g = self.epoch_tx.lock();
        g.entry(network_id.to_string())
            .or_insert_with(|| watch::channel(0).0)
            .subscribe()
    }

    /// The network a device belongs to (if any).
    pub async fn network_of(&self, device_id: &str) -> Result<Option<String>> {
        Ok(db::get_device(&self.pool, device_id).await?.map(|d| d.network_id))
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn create_network(&self, name: &str) -> Result<Network> {
        let idx = self.net_index.fetch_add(1, Ordering::Relaxed);
        let octet = (idx % 200) as u8 + 16;
        let net = Network {
            id: format!("net-{}", self.next_seq()),
            name: name.to_string(),
            ipv4_pool: format!("100.72.{octet}.0/24"),
            ipv6_ula: format!("fd72:15ab:{:04x}::/48", idx & 0xffff),
            config_epoch: 0,
        };
        db::insert_network(&self.pool, &net).await?;
        self.epoch_tx.lock().insert(net.id.clone(), watch::channel(0).0);
        Ok(net)
    }

    pub async fn create_invite(
        &self,
        network_id: &str,
        expires_at: Option<i64>,
        max_uses: Option<u32>,
    ) -> Result<Invite> {
        if db::get_network(&self.pool, network_id).await?.is_none() {
            return Err(SqlStoreError::NetworkNotFound);
        }
        let invite = Invite {
            // CSPRNG, 128-bit — an invite code authorizes enrollment, so it must be
            // unguessable (NOT a sequential id an attacker can enumerate).
            code: crate::auth::random_hex(16),
            network_id: network_id.to_string(),
            expires_at,
            max_uses,
            uses: 0,
        };
        db::insert_invite(&self.pool, &invite).await?;
        Ok(invite)
    }

    /// Redeem an invite and enroll a device. Returns the device AND a freshly-issued
    /// per-device auth token — the device's only credential for its own config read /
    /// endpoint writes (so a guessable `dev-N` id is no longer authority). The token
    /// is returned ONCE here and never echoed by any other endpoint.
    pub async fn enroll(&self, invite_code: &str, name: &str, wg_public_key: &str, now: i64) -> Result<(Device, String)> {
        let invite = db::get_invite(&self.pool, invite_code)
            .await?
            .ok_or(SqlStoreError::InvalidInvite)?;
        if !invite.is_redeemable(now) {
            return Err(SqlStoreError::InvalidInvite);
        }
        let net = db::get_network(&self.pool, &invite.network_id)
            .await?
            .ok_or(SqlStoreError::NetworkNotFound)?;

        let (v4, v6) = self.allocate_address(&net).await?;
        let device = Device {
            id: format!("dev-{}", self.next_seq()),
            network_id: net.id.clone(),
            name: name.to_string(),
            wg_public_key: wg_public_key.to_string(),
            address_v4: Some(v4.to_string()),
            address_v6: Some(v6.to_string()),
            status: DeviceStatus::Active,
        };
        let token = crate::auth::random_hex(32);
        db::insert_device(&self.pool, &device).await?;
        db::set_device_token(&self.pool, &device.id, &token).await?;
        db::incr_invite_uses(&self.pool, invite_code).await?;
        self.bump_and_notify(&net.id).await?;
        Ok((device, token))
    }

    /// A device's enroll-issued auth token (None if unknown or pre-token).
    pub async fn device_token(&self, device_id: &str) -> Result<Option<String>> {
        Ok(db::get_device_token(&self.pool, device_id).await?)
    }

    /// Lowest-free dual-stack address in the device range, derived from the
    /// network's active devices (recycling-correct).
    async fn allocate_address(&self, net: &Network) -> Result<(Ipv4Addr, Ipv6Addr)> {
        let base = parse_v4_base(&net.ipv4_pool)?;
        let v6p = parse_v6_prefix(&net.ipv6_ula)?;
        let used: HashSet<u8> = db::active_device_v4s(&self.pool, &net.id)
            .await?
            .iter()
            .filter_map(|a| a.parse::<Ipv4Addr>().ok())
            .map(|ip| ip.octets()[3])
            .collect();
        let host = (DEVICE_HOST_MIN..=DEVICE_HOST_MAX)
            .find(|h| !used.contains(h))
            .ok_or(SqlStoreError::PoolExhausted)?;
        let v4 = Ipv4Addr::new(base[0], base[1], base[2], host);
        let v6 = Ipv6Addr::new(v6p[0], v6p[1], v6p[2], 1, 0, 0, 0, host as u16);
        Ok((v4, v6))
    }

    /// Batch-register devices parsed from a wg.conf (`fp import`). Fixed addresses
    /// are stored verbatim (so they're honored by the derived-from-active-set
    /// allocator on later enrolls); existing public keys are skipped (idempotent).
    /// One epoch bump for the whole batch. Admin-gated at the HTTP layer.
    pub async fn import_devices(&self, network_id: &str, devices: &[ImportDevice]) -> Result<ImportResult> {
        if db::get_network(&self.pool, network_id).await?.is_none() {
            return Err(SqlStoreError::NetworkNotFound);
        }
        let mut seen: HashSet<String> = db::list_devices(&self.pool, network_id)
            .await?
            .into_iter()
            .map(|d| d.wg_public_key)
            .collect();
        let mut created = Vec::new();
        let mut skipped = Vec::new();
        for d in devices {
            if d.wg_public_key.is_empty() || !seen.insert(d.wg_public_key.clone()) {
                skipped.push(d.wg_public_key.clone());
                continue;
            }
            let device = Device {
                id: format!("dev-{}", self.next_seq()),
                network_id: network_id.to_string(),
                name: d.name.clone(),
                wg_public_key: d.wg_public_key.clone(),
                address_v4: d.address_v4.clone(),
                address_v6: d.address_v6.clone(),
                status: DeviceStatus::Active,
            };
            db::insert_device(&self.pool, &device).await?;
            if !d.endpoints.is_empty() {
                db::set_device_endpoints(&self.pool, &device.id, &d.endpoints).await?;
            }
            created.push(device);
        }
        if !created.is_empty() {
            self.bump_and_notify(network_id).await?;
        }
        Ok(ImportResult { created, skipped })
    }

    pub async fn list_networks(&self) -> Result<Vec<Network>> {
        Ok(db::list_networks(&self.pool).await?)
    }

    // ── admin accounts (auth) ──
    pub async fn count_admins(&self) -> Result<i64> {
        Ok(db::count_admins(&self.pool).await?)
    }
    pub async fn admin_hash(&self, username: &str) -> Result<Option<String>> {
        Ok(db::admin_hash(&self.pool, username).await?)
    }
    pub async fn create_admin(&self, username: &str, hash: &str, now: i64) -> Result<()> {
        db::create_admin(&self.pool, username, hash, now).await?;
        Ok(())
    }
    pub async fn update_admin_password(&self, username: &str, hash: &str) -> Result<()> {
        db::update_admin_password(&self.pool, username, hash).await?;
        Ok(())
    }
    pub async fn list_admins(&self) -> Result<Vec<String>> {
        Ok(db::list_admins(&self.pool).await?)
    }
    pub async fn delete_admin(&self, username: &str) -> Result<()> {
        db::delete_admin(&self.pool, username).await?;
        Ok(())
    }
    pub async fn record_audit(&self, ts: i64, actor: &str, action: &str) {
        let _ = db::insert_audit(&self.pool, ts, actor, action).await;
    }
    pub async fn recent_audit(&self, limit: i64) -> Result<Vec<crate::domain::AuditEntry>> {
        Ok(db::list_audit(&self.pool, limit).await?)
    }

    pub async fn list_devices(&self, network_id: &str) -> Result<Vec<Device>> {
        if db::get_network(&self.pool, network_id).await?.is_none() {
            return Err(SqlStoreError::NetworkNotFound);
        }
        Ok(db::list_devices(&self.pool, network_id).await?)
    }

    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        let device = db::get_device(&self.pool, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        db::set_device_status(&self.pool, device_id, "revoked").await?;
        self.bump_and_notify(&device.network_id).await?;
        Ok(())
    }

    /// Rename a device. The name is metadata (not in any peer config), so no epoch
    /// bump / config-pull is needed. Returns the updated device.
    pub async fn rename_device(&self, device_id: &str, name: &str) -> Result<Device> {
        let mut device = db::get_device(&self.pool, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        db::set_device_name(&self.pool, device_id, name).await?;
        device.name = name.to_string();
        Ok(device)
    }

    /// List a network's invites (for the admin used/unused view).
    pub async fn list_invites(&self, network_id: &str) -> Result<Vec<crate::domain::Invite>> {
        Ok(db::list_invites(&self.pool, network_id).await?)
    }

    /// Read a device's editable wg settings (raw JSON: {mtu, dns, endpoint}).
    pub async fn device_settings(&self, device_id: &str) -> Result<String> {
        if db::get_device(&self.pool, device_id).await?.is_none() {
            return Err(SqlStoreError::DeviceNotFound);
        }
        Ok(db::get_device_settings(&self.pool, device_id).await?)
    }

    /// Set a device's editable wg settings. Bumps the epoch so nodes reconcile the
    /// MTU/DNS/endpoint changes.
    pub async fn set_device_settings(&self, device_id: &str, settings_json: &str) -> Result<()> {
        let dev = db::get_device(&self.pool, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        db::set_device_settings(&self.pool, device_id, settings_json).await?;
        self.bump_and_notify(&dev.network_id).await?;
        Ok(())
    }

    /// Advertise a subnet route from a device (created UNAPPROVED — no config effect
    /// until approved, so no epoch bump yet).
    pub async fn advertise_route(&self, device_id: &str, prefix: &str) -> Result<Route> {
        let dev = db::get_device(&self.pool, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        let route = Route {
            id: format!("route-{}", self.next_seq()),
            network_id: dev.network_id,
            device_id: device_id.to_string(),
            prefix: prefix.to_string(),
            approved: false,
        };
        db::insert_route(&self.pool, &route).await?;
        Ok(route)
    }

    pub async fn list_device_routes(&self, device_id: &str) -> Result<Vec<Route>> {
        Ok(db::list_routes_for_device(&self.pool, device_id).await?)
    }

    /// Approve a route → it now appears in peer allowed-ips; bump the epoch so nodes
    /// reconcile the new AllowedIPs without a restart (REVOKE-1 path).
    pub async fn approve_route(&self, route_id: &str) -> Result<()> {
        let r = db::get_route(&self.pool, route_id)
            .await?
            .ok_or(SqlStoreError::RouteNotFound)?;
        db::set_route_approved(&self.pool, route_id, true).await?;
        self.bump_and_notify(&r.network_id).await?;
        Ok(())
    }

    /// Delete a route. Bumps the epoch only if it was approved (i.e. in the config).
    pub async fn delete_route(&self, route_id: &str) -> Result<()> {
        let r = db::get_route(&self.pool, route_id)
            .await?
            .ok_or(SqlStoreError::RouteNotFound)?;
        db::delete_route(&self.pool, route_id).await?;
        if r.approved {
            self.bump_and_notify(&r.network_id).await?;
        }
        Ok(())
    }

    /// Record a node-reported traffic stats sample (cumulative rx/tx + per-peer blob).
    pub async fn report_stats(&self, device_id: &str, rx: i64, tx: i64, peers_json: &str, at: i64) -> Result<()> {
        db::upsert_device_stats(&self.pool, device_id, rx, tx, peers_json, at).await?;
        Ok(())
    }

    /// A device's latest stats `(rx, tx, peers_json, updated_at)`.
    pub async fn device_stats(&self, device_id: &str) -> Result<Option<(i64, i64, String, i64)>> {
        Ok(db::get_device_stats(&self.pool, device_id).await?)
    }

    /// Per-device `(device_id, rx, tx, updated_at)` rollup for a network.
    pub async fn network_stats(&self, network_id: &str) -> Result<Vec<(String, i64, i64, i64)>> {
        Ok(db::list_network_stats(&self.pool, network_id).await?)
    }

    pub async fn device_config(&self, device_id: &str) -> Result<DeviceConfig> {
        let me = db::get_device(&self.pool, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        if me.status != DeviceStatus::Active {
            return Err(SqlStoreError::DeviceNotFound);
        }
        let net = db::get_network(&self.pool, &me.network_id)
            .await?
            .ok_or(SqlStoreError::NetworkNotFound)?;
        // Approved subnet routes in this network, as (advertising device, prefix).
        let approved = db::approved_routes_for_network(&self.pool, &me.network_id).await?;
        // This device's own editable wg settings (MTU / DNS apply locally).
        let my_settings: serde_json::Value =
            serde_json::from_str(&db::get_device_settings(&self.pool, device_id).await?).unwrap_or_default();
        let mtu = my_settings.get("mtu").and_then(|v| v.as_i64()).map(|m| m as i32);
        let dns: Vec<String> = my_settings
            .get("dns")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let mut peers = Vec::new();
        for d in db::list_devices(&self.pool, &me.network_id)
            .await?
            .into_iter()
            .filter(|d| d.id != me.id && d.status == DeviceStatus::Active)
        {
            let mut allowed_ips = Vec::new();
            if let Some(v4) = &d.address_v4 {
                allowed_ips.push(format!("{v4}/32"));
            }
            if let Some(v6) = &d.address_v6 {
                allowed_ips.push(format!("{v6}/128"));
            }
            // Subnet Router: this peer also routes its APPROVED prefixes.
            for (did, prefix) in &approved {
                if did == &d.id {
                    allowed_ips.push(prefix.clone());
                }
            }
            let mut endpoints = db::get_device_endpoints(&self.pool, &d.id).await?;
            // Admin endpoint override for this peer takes priority over reported ones.
            let ps: serde_json::Value =
                serde_json::from_str(&db::get_device_settings(&self.pool, &d.id).await?).unwrap_or_default();
            if let Some(ep) = ps.get("endpoint").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
                endpoints.insert(0, ep.to_string());
            }
            peers.push(PeerConfig {
                wg_public_key: d.wg_public_key,
                allowed_ips,
                endpoints,
            });
        }
        let relays = db::list_relays(&self.pool, &me.network_id).await?;
        Ok(DeviceConfig {
            network_id: me.network_id,
            config_epoch: net.config_epoch,
            address_v4: me.address_v4,
            address_v6: me.address_v6,
            peers,
            relays,
            mtu,
            dns,
        })
    }

    /// Register a relay node. `network_id = None` = shared/official.
    /// `stun_url` defaults to `url` (the relay doubles as STUN).
    pub async fn register_relay(
        &self,
        region: &str,
        url: &str,
        network_id: Option<String>,
        anytls: bool,
        stun_url: Option<String>,
    ) -> Result<RelayNode> {
        let relay = RelayNode {
            id: format!("relay-{}", self.seq.fetch_add(1, Ordering::Relaxed)),
            region: region.to_string(),
            url: url.to_string(),
            network_id,
            anytls,
            stun_url: stun_url.or_else(|| Some(url.to_string())),
        };
        db::insert_relay(&self.pool, &relay).await?;
        Ok(relay)
    }

    /// Relays usable by a network: those scoped to it plus shared/official ones.
    pub async fn list_relays(&self, network_id: &str) -> Result<Vec<RelayNode>> {
        Ok(db::list_relays(&self.pool, network_id).await?)
    }

    /// A device reports its current candidate endpoints; peers pick them up on
    /// their next config-pull/push (epoch bumped to notify watchers).
    pub async fn set_endpoints(&self, device_id: &str, endpoints: &[String]) -> Result<()> {
        let device = db::get_device(&self.pool, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        db::set_device_endpoints(&self.pool, device_id, endpoints).await?;
        self.bump_and_notify(&device.network_id).await?;
        Ok(())
    }
}

fn parse_v4_base(pool: &str) -> Result<[u8; 3]> {
    let addr = pool.split('/').next().unwrap_or(pool);
    let ip: Ipv4Addr = addr.parse().map_err(|_| SqlStoreError::BadPool(pool.to_string()))?;
    let o = ip.octets();
    Ok([o[0], o[1], o[2]])
}

fn parse_v6_prefix(ula: &str) -> Result<[u16; 3]> {
    // "fd72:15ab:0000::/48" -> [0xfd72, 0x15ab, 0x0000]
    let head = ula.split("::").next().unwrap_or(ula).split('/').next().unwrap_or(ula);
    let parts: Vec<&str> = head.split(':').filter(|s| !s.is_empty()).collect();
    if parts.len() < 3 {
        return Err(SqlStoreError::BadPool(ula.to_string()));
    }
    let mut out = [0u16; 3];
    for (i, p) in parts.iter().take(3).enumerate() {
        out[i] = u16::from_str_radix(p, 16).map_err(|_| SqlStoreError::BadPool(ula.to_string()))?;
    }
    Ok(out)
}

#[cfg(test)]
mod test {
    use super::*;

    async fn store() -> SqlStore {
        // Each :memory: connection is a distinct DB; the pool is capped at 1
        // connection via Any default? Force a single shared DB by using a named
        // shared-cache in-memory database.
        SqlStore::connect("sqlite:file:memdb_test?mode=memory&cache=shared")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn import_persists_fixed_addresses_endpoints_and_dedups() {
        // Own isolated DB: the shared `store()` DB hardcodes octets by row count,
        // so creating networks there would shift other tests' expectations.
        let s = SqlStore::connect("sqlite:file:memdb_import_test?mode=memory&cache=shared")
            .await
            .unwrap();
        let net = s.create_network("home").await.unwrap();
        let dev = |name: &str, key: &str, v4: &str, ep: Vec<String>| ImportDevice {
            name: name.into(),
            wg_public_key: key.into(),
            address_v4: Some(v4.into()),
            address_v6: None,
            endpoints: ep,
        };

        let r = s
            .import_devices(
                &net.id,
                &[
                    dev("hub", "k-hub", "10.0.0.1", vec![]),
                    dev("laptop", "k-laptop", "10.0.0.5", vec!["203.0.113.7:51820".into()]),
                ],
            )
            .await
            .unwrap();
        assert_eq!(r.created.len(), 2);
        assert!(r.skipped.is_empty());

        // Fixed addresses persisted verbatim.
        let devs = s.list_devices(&net.id).await.unwrap();
        let laptop = devs.iter().find(|d| d.name == "laptop").unwrap();
        assert_eq!(laptop.address_v4.as_deref(), Some("10.0.0.5"));

        // The hub's pulled config sees laptop as a peer carrying its pinned endpoint.
        let hub = devs.iter().find(|d| d.name == "hub").unwrap();
        let cfg = s.device_config(&hub.id).await.unwrap();
        let peer = cfg.peers.iter().find(|p| p.wg_public_key == "k-laptop").unwrap();
        assert_eq!(peer.endpoints, vec!["203.0.113.7:51820".to_string()]);

        // Re-import is idempotent.
        let r2 = s.import_devices(&net.id, &[dev("dup", "k-laptop", "10.0.0.5", vec![])]).await.unwrap();
        assert!(r2.created.is_empty());
        assert_eq!(r2.skipped, vec!["k-laptop".to_string()]);
        assert_eq!(s.list_devices(&net.id).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn full_persistent_enroll_loop() {
        let s = store().await;
        let net = s.create_network("home").await.unwrap();
        let inv = s.create_invite(&net.id, None, Some(5)).await.unwrap();

        let (d1, _) = s.enroll(&inv.code, "laptop", "k1", 1000).await.unwrap();
        assert_eq!(d1.address_v4.as_deref(), Some("100.72.16.100"));
        assert_eq!(d1.address_v6.as_deref(), Some("fd72:15ab:0:1::64"));

        let (d2, _) = s.enroll(&inv.code, "phone", "k2", 1000).await.unwrap();
        assert_eq!(d2.address_v4.as_deref(), Some("100.72.16.101"));

        // config of d1 lists d2 as a peer
        let cfg = s.device_config(&d1.id).await.unwrap();
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].wg_public_key, "k2");
        assert!(cfg.config_epoch >= 2);

        // revoke d2 → freed addr reused, d2 cut off
        s.revoke_device(&d2.id).await.unwrap();
        assert!(s.device_config(&d2.id).await.is_err());
        let (d3, _) = s.enroll(&inv.code, "tablet", "k3", 1000).await.unwrap();
        assert_eq!(d3.address_v4.as_deref(), Some("100.72.16.101")); // recycled
        assert_eq!(s.list_devices(&net.id).await.unwrap().len(), 3); // soft-delete keeps rows
    }

    #[tokio::test]
    async fn endpoints_distributed_to_peers() {
        let s = SqlStore::connect("sqlite:file:memdb_ep?mode=memory&cache=shared")
            .await
            .unwrap();
        let net = s.create_network("home").await.unwrap();
        let inv = s.create_invite(&net.id, None, None).await.unwrap();
        let (a, _) = s.enroll(&inv.code, "A", "kA", 1000).await.unwrap();
        let (b, _) = s.enroll(&inv.code, "B", "kB", 1000).await.unwrap();

        // before B reports, A sees no endpoints for peer B
        let cfg = s.device_config(&a.id).await.unwrap();
        assert!(cfg.peers[0].endpoints.is_empty());

        // B reports endpoints → A's config-pull carries them
        let eps = vec!["192.168.31.203:51820".to_string(), "100.72.16.2:51820".to_string()];
        s.set_endpoints(&b.id, &eps).await.unwrap();
        let cfg = s.device_config(&a.id).await.unwrap();
        assert_eq!(cfg.peers[0].wg_public_key, "kB");
        assert_eq!(cfg.peers[0].endpoints, eps);
    }

    #[tokio::test]
    async fn relay_directory_persisted_and_in_device_config() {
        let s = SqlStore::connect("sqlite:file:memdb_relay?mode=memory&cache=shared")
            .await
            .unwrap();
        let net = s.create_network("home").await.unwrap();
        let inv = s.create_invite(&net.id, None, None).await.unwrap();
        let (a, _) = s.enroll(&inv.code, "A", "kA", 1000).await.unwrap();

        // shared/official relay (anytls, STUN defaults to url) + a network-scoped one
        let shared = s
            .register_relay("eu", "relay.example.org:443", None, true, None)
            .await
            .unwrap();
        assert!(shared.anytls);
        assert_eq!(shared.stun_url.as_deref(), Some("relay.example.org:443"));
        s.register_relay(
            "us",
            "198.51.100.7:3478",
            Some(net.id.clone()),
            false,
            Some("198.51.100.7:3478".into()),
        )
        .await
        .unwrap();

        // list: scoped + shared; an unrelated network sees only the shared one
        assert_eq!(s.list_relays(&net.id).await.unwrap().len(), 2);
        let other = s.create_network("other").await.unwrap();
        assert_eq!(s.list_relays(&other.id).await.unwrap().len(), 1);

        // a device pulls the directory in its config
        let cfg = s.device_config(&a.id).await.unwrap();
        assert_eq!(cfg.relays.len(), 2);
        assert!(cfg.relays.iter().any(|r| r.url == "relay.example.org:443" && r.anytls));
    }

    #[tokio::test]
    async fn invite_validation_persisted() {
        let s = SqlStore::connect("sqlite:file:memdb_inv?mode=memory&cache=shared")
            .await
            .unwrap();
        let net = s.create_network("n").await.unwrap();
        let inv = s.create_invite(&net.id, None, Some(1)).await.unwrap();
        assert!(s.enroll(&inv.code, "a", "ka", 1000).await.is_ok());
        // use limit hit
        assert!(matches!(
            s.enroll(&inv.code, "b", "kb", 1000).await,
            Err(SqlStoreError::InvalidInvite)
        ));
        // unknown invite
        assert!(matches!(
            s.enroll("nope", "c", "kc", 1000).await,
            Err(SqlStoreError::InvalidInvite)
        ));
    }
}
