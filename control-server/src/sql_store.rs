//! Persistent coordination store backed by SQL (sqlx `Any`).
//!
//! Same coordination logic as [`crate::state::Store`] but durable: networks,
//! invites, devices live in the DB, and IP allocation is **derived from the
//! current active-device set** (so it survives restarts and respects recycling).
//! Verified end-to-end on in-memory SQLite; production points it at PostgreSQL.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use portable_atomic::AtomicU64;
use sqlx::AnyPool;
use tokio::sync::watch;

use crate::domain::{
    Device, DeviceConfig, DeviceStatus, ImportDevice, ImportResult, Invite, Network, PeerConfig, RelayNode, Route,
    is_default_prefix, normalize_prefix,
};
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
    #[error("invalid route prefix")]
    InvalidPrefix,
    #[error("invalid 32-byte public key")]
    InvalidKey,
    #[error("invalid IPv4 address")]
    InvalidAddress,
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
    net_index: AtomicU64,
    /// Per-network config-epoch broadcaster for WS push (ephemeral, in-process).
    epoch_tx: Mutex<HashMap<String, watch::Sender<u64>>>,
}

impl SqlStore {
    /// Connect, migrate, and seed id generation from existing rows.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = db::connect(url).await?;
        db::migrate(&pool).await?;
        let nets = db::count_networks(&pool).await?; // pool spread only; IDs use the durable sequence
        Ok(Self {
            pool,
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

    async fn next_seq(&self) -> Result<i64> {
        let mut attempt = 0;
        loop {
            match self.next_seq_once().await {
                Err(SqlStoreError::Db(error)) if crate::integrity::retryable(&error) && attempt < 7 => {
                    tokio::time::sleep(std::time::Duration::from_millis(10 << attempt)).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    async fn next_seq_once(&self) -> Result<i64> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        let id = crate::integrity::next(&mut tx).await?;
        tx.commit().await?;
        Ok(id)
    }

    async fn notify(&self, network_id: &str) {
        // The durable epoch is already committed. A failed optional notification
        // must not turn a successful enrollment/token rotation into an error.
        match db::get_network(&self.pool, network_id).await {
            Ok(Some(net)) => {
                if let Some(tx) = self.epoch_tx.lock().get(network_id) {
                    tx.send_if_modified(|epoch| {
                        if *epoch >= net.config_epoch { return false; }
                        *epoch = net.config_epoch;
                        true
                    });
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "committed epoch notification failed"),
        }
    }

    pub async fn create_network(&self, name: &str) -> Result<Network> {
        let idx = self.net_index.fetch_add(1, Ordering::Relaxed);
        let octet = (idx % 200) as u8 + 16;
        let net = Network {
            id: format!("net-{}", self.next_seq().await?),
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
        let key = fluxpeer_sdk::key::normalize(wg_public_key).ok_or(SqlStoreError::InvalidKey)?;
        let mut attempt = 0;
        loop {
            match self.enroll_once(invite_code, name, &key, now).await {
                Err(SqlStoreError::Db(error)) if crate::integrity::retryable(&error) && attempt < 7 => {
                    tokio::time::sleep(std::time::Duration::from_millis(10 << attempt)).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    async fn enroll_once(&self, invite_code: &str, name: &str, key: &str, now: i64) -> Result<(Device, String)> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        let result = async {
            let invite = db::get_invite(&mut *tx, invite_code).await?.ok_or(SqlStoreError::InvalidInvite)?;
            if invite.expires_at.is_some_and(|expiry| now >= expiry) {
                return Err(SqlStoreError::InvalidInvite);
            }
            let net = db::get_network(&mut *tx, &invite.network_id).await?.ok_or(SqlStoreError::NetworkNotFound)?;
            let devices = db::list_devices(&mut *tx, &net.id).await?;
            let token = crate::auth::random_hex(32);
            if let Some(device) = devices.iter().find(|device| device.status == DeviceStatus::Active && device.wg_public_key == key) {
                // Only active identities are idempotent; tombstones remain intact.
                db::set_device_token(&mut *tx, &device.id, &token).await?;
                return Ok((device.clone(), token));
            }
            let consumed = sqlx::query("UPDATE invite SET uses = uses + 1 WHERE code = $1 AND (expires_at IS NULL OR expires_at > $2) AND (max_uses IS NULL OR uses < max_uses)")
                .bind(invite_code).bind(now).execute(&mut *tx).await?.rows_affected();
            if consumed != 1 { return Err(SqlStoreError::InvalidInvite); }
            let (v4, v6) = Self::allocate_address(&net, &devices)?;
            let device = Device {
                id: format!("dev-{}", crate::integrity::next(&mut tx).await?),
                network_id: net.id.clone(), name: name.to_owned(), wg_public_key: key.to_owned(),
                address_v4: Some(v4.to_string()), address_v6: Some(v6.to_string()), status: DeviceStatus::Active,
            };
            db::insert_device(&mut *tx, &device).await?;
            db::set_device_token(&mut *tx, &device.id, &token).await?;
            db::bump_network_epoch(&mut *tx, &net.id).await?;
            Ok((device, token))
        }.await;
        match result {
            Ok(result) => {
                tx.commit().await?;
                self.notify(&result.0.network_id).await;
                Ok(result)
            }
            Err(error) => {
                if let Err(rollback) = tx.rollback().await { tracing::warn!(%rollback, "transaction rollback failed; preserving original error"); }
                Err(error)
            }
        }
    }

    /// A device's enroll-issued auth token (None if unknown or pre-token).
    pub async fn device_token(&self, device_id: &str) -> Result<Option<String>> {
        Ok(db::get_device_token(&self.pool, device_id).await?)
    }

    /// Lowest-free dual-stack address in the device range, derived from the
    /// network's active devices (recycling-correct).
    fn allocate_address(net: &Network, devices: &[Device]) -> Result<(Ipv4Addr, Ipv6Addr)> {
        let base = parse_v4_base(&net.ipv4_pool)?;
        let v6p = parse_v6_prefix(&net.ipv6_ula)?;
        let used: HashSet<u8> = devices.iter().filter(|d| d.status == DeviceStatus::Active)
            .filter_map(|d| d.address_v4.as_deref())
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
        // Validate all keys before opening the batch; malformed input creates no
        // partial import. The same database lock coordinates imports with enroll.
        let devices = devices.iter().cloned().map(|mut d| {
            d.address_v4 = d.address_v4.as_deref().map(|address| address.parse::<Ipv4Addr>()
                .map(|ip| ip.to_string()).map_err(|_| SqlStoreError::InvalidAddress)).transpose()?;
            Ok(d)
        }).collect::<Result<Vec<_>>>()?;
        let keys = devices.iter().map(|d| fluxpeer_sdk::key::normalize(&d.wg_public_key)
            .ok_or(SqlStoreError::InvalidKey)).collect::<Result<Vec<_>>>()?;
        let mut attempt = 0;
        loop {
            match self.import_once(network_id, &devices, &keys).await {
                Err(SqlStoreError::Db(error)) if crate::integrity::retryable(&error) && attempt < 7 => {
                    tokio::time::sleep(std::time::Duration::from_millis(10 << attempt)).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    async fn import_once(&self, network_id: &str, devices: &[ImportDevice], keys: &[String]) -> Result<ImportResult> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        let result = async {
            if db::get_network(&mut *tx, network_id).await?.is_none() { return Err(SqlStoreError::NetworkNotFound); }
            let mut seen: HashSet<_> = db::list_devices(&mut *tx, network_id).await?
                .into_iter().filter(|d| d.status == DeviceStatus::Active).map(|d| d.wg_public_key).collect();
            let mut created = Vec::new();
            let mut skipped = Vec::new();
            for (d, key) in devices.iter().zip(keys) {
                if !seen.insert(key.clone()) { skipped.push(key.clone()); continue; }
                let device = Device {
                    id: format!("dev-{}", crate::integrity::next(&mut tx).await?),
                    network_id: network_id.to_owned(), name: d.name.clone(), wg_public_key: key.clone(),
                    address_v4: d.address_v4.clone(), address_v6: d.address_v6.clone(), status: DeviceStatus::Active,
                };
                db::insert_device(&mut *tx, &device).await?;
                db::set_device_endpoints(&mut *tx, &device.id, &d.endpoints).await?;
                created.push(device);
            }
            if !created.is_empty() { db::bump_network_epoch(&mut *tx, network_id).await?; }
            Ok(ImportResult { created, skipped })
        }.await;
        match result {
            Ok(result) => { tx.commit().await?; self.notify(network_id).await; Ok(result) }
            Err(error) => {
                if let Err(rollback) = tx.rollback().await { tracing::warn!(%rollback, "transaction rollback failed; preserving original error"); }
                Err(error)
            }
        }
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
        let mut attempt = 0;
        loop {
            match self.revoke_device_once(device_id).await {
                Err(SqlStoreError::Db(error)) if crate::integrity::retryable(&error) && attempt < 7 => {
                    tokio::time::sleep(std::time::Duration::from_millis(10 << attempt)).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    async fn revoke_device_once(&self, device_id: &str) -> Result<()> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        let device = db::get_device(&mut *tx, device_id).await?.ok_or(SqlStoreError::DeviceNotFound)?;
        // Revoke the credential and release addresses while retaining the tombstone.
        sqlx::query("UPDATE device SET status = 'revoked', address_v4 = NULL, address_v6 = NULL, auth_token = NULL WHERE id = $1")
            .bind(device_id).execute(&mut *tx).await?;
        db::bump_network_epoch(&mut *tx, &device.network_id).await?;
        tx.commit().await?;
        self.notify(&device.network_id).await;
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
            id: format!("route-{}", self.next_seq().await?),
            network_id: dev.network_id,
            device_id: device_id.to_string(),
            prefix: normalize_prefix(prefix).ok_or(SqlStoreError::InvalidPrefix)?,
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
        // Exit-ness (AD-1/AD-2): a device is an exit iff it owns an APPROVED
        // default route. The control-plane is the single source of truth.
        let is_exit = |device_id: &str| {
            approved
                .iter()
                .any(|(did, prefix)| did == device_id && is_default_prefix(prefix))
        };
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
            let exit = is_exit(&d.id);
            peers.push(PeerConfig {
                wg_public_key: d.wg_public_key,
                allowed_ips,
                endpoints,
                exit,
            });
        }
        let self_exit = is_exit(&me.id);
        let relays = db::list_relays(&self.pool, &me.network_id).await?;
        Ok(DeviceConfig {
            overlay_cidrs: vec![net.ipv4_pool, net.ipv6_ula],
            network_id: me.network_id,
            config_epoch: net.config_epoch,
            address_v4: me.address_v4,
            address_v6: me.address_v6,
            peers,
            relays,
            mtu,
            dns,
            self_exit,
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
        node_id: Option<String>,
    ) -> Result<RelayNode> {
        let relay = RelayNode {
            id: format!("relay-{}", self.next_seq().await?),
            region: region.to_string(),
            url: url.to_string(),
            network_id,
            anytls,
            stun_url: stun_url.or_else(|| Some(url.to_string())),
            node_id,
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
                    dev("hub", "86962e9c29953406be643f81bdaee3f64000c0919d2857e7593f914d82c276ae", "10.0.0.1", vec![]),
                    dev("laptop", "173c9ce184d2a3716657525df4491d0340476de3b133a1968a30067ac75b3ee0", "10.0.0.5", vec!["203.0.113.7:51820".into()]),
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
        let peer = cfg.peers.iter().find(|p| p.wg_public_key == "173c9ce184d2a3716657525df4491d0340476de3b133a1968a30067ac75b3ee0").unwrap();
        assert_eq!(peer.endpoints, vec!["203.0.113.7:51820".to_string()]);

        // Re-import is idempotent.
        let r2 = s.import_devices(&net.id, &[dev("dup", "173c9ce184d2a3716657525df4491d0340476de3b133a1968a30067ac75b3ee0", "10.0.0.5", vec![])]).await.unwrap();
        assert!(r2.created.is_empty());
        assert_eq!(r2.skipped, vec!["173c9ce184d2a3716657525df4491d0340476de3b133a1968a30067ac75b3ee0".to_string()]);
        assert_eq!(s.list_devices(&net.id).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn full_persistent_enroll_loop() {
        let s = store().await;
        let net = s.create_network("home").await.unwrap();
        let inv = s.create_invite(&net.id, None, Some(5)).await.unwrap();

        let (d1, _) = s.enroll(&inv.code, "laptop", "6ab9f1eb8f7d3388f4f9d586f66e99fd54080df2c446f0e58668b09c08a16dd0", 1000).await.unwrap();
        assert_eq!(d1.address_v4.as_deref(), Some("100.72.16.100"));
        assert_eq!(d1.address_v6.as_deref(), Some("fd72:15ab:0:1::64"));

        let (d2, _) = s.enroll(&inv.code, "phone", "015f7e6bc5aeaf483724089e9252cc13b50951a6b69412522765cff4d780306e", 1000).await.unwrap();
        assert_eq!(d2.address_v4.as_deref(), Some("100.72.16.101"));

        // config of d1 lists d2 as a peer
        let cfg = s.device_config(&d1.id).await.unwrap();
        assert_eq!(cfg.overlay_cidrs, vec![net.ipv4_pool.clone(), net.ipv6_ula.clone()]);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].wg_public_key, "015f7e6bc5aeaf483724089e9252cc13b50951a6b69412522765cff4d780306e");
        assert!(cfg.config_epoch >= 2);

        // revoke d2 → freed addr reused, d2 cut off
        s.revoke_device(&d2.id).await.unwrap();
        assert_eq!(s.device_config(&d1.id).await.unwrap().overlay_cidrs, cfg.overlay_cidrs);
        assert!(s.device_config(&d2.id).await.is_err());
        let (d3, _) = s.enroll(&inv.code, "tablet", "2f5052c9fd15b19a18c584d01363568198613f0c34e84409ef7938709a159ec2", 1000).await.unwrap();
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
        let (a, _) = s.enroll(&inv.code, "A", "2f93927dcc75eadefc95d934fe3fda1226111b9d5464b5de2e3d6e0dc1422f67", 1000).await.unwrap();
        let (b, _) = s.enroll(&inv.code, "B", "591e59cef10116c9a0d6ccf709d50c44a024ff5dbaa1e38841223c4027e9f584", 1000).await.unwrap();

        // before B reports, A sees no endpoints for peer B
        let cfg = s.device_config(&a.id).await.unwrap();
        assert!(cfg.peers[0].endpoints.is_empty());

        // B reports endpoints → A's config-pull carries them
        let eps = vec!["192.168.31.203:51820".to_string(), "100.72.16.2:51820".to_string()];
        s.set_endpoints(&b.id, &eps).await.unwrap();
        let cfg = s.device_config(&a.id).await.unwrap();
        assert_eq!(cfg.peers[0].wg_public_key, "591e59cef10116c9a0d6ccf709d50c44a024ff5dbaa1e38841223c4027e9f584");
        assert_eq!(cfg.peers[0].endpoints, eps);
    }

    #[tokio::test]
    async fn relay_directory_persisted_and_in_device_config() {
        let s = SqlStore::connect("sqlite:file:memdb_relay?mode=memory&cache=shared")
            .await
            .unwrap();
        let net = s.create_network("home").await.unwrap();
        let inv = s.create_invite(&net.id, None, None).await.unwrap();
        let (a, _) = s.enroll(&inv.code, "A", "2f93927dcc75eadefc95d934fe3fda1226111b9d5464b5de2e3d6e0dc1422f67", 1000).await.unwrap();

        // shared/official relay (anytls, STUN defaults to url) + a network-scoped one
        let shared = s
            .register_relay("eu", "relay.example.org:443", None, true, None, Some("edge-eu".into()))
            .await
            .unwrap();
        assert!(shared.anytls);
        assert_eq!(shared.node_id.as_deref(), Some("edge-eu"));
        assert_eq!(shared.stun_url.as_deref(), Some("relay.example.org:443"));
        s.register_relay(
            "us",
            "198.51.100.7:3478",
            Some(net.id.clone()),
            false,
            Some("198.51.100.7:3478".into()),
            None,
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
        assert!(cfg.relays.iter().any(|r| r.url == "relay.example.org:443" && r.anytls && r.node_id.as_deref() == Some("edge-eu")));
        // Fresh store connection must read identity from SQL, not process memory.
        let reopened = SqlStore::connect("sqlite:file:memdb_relay?mode=memory&cache=shared").await.unwrap();
        assert!(reopened.device_config(&a.id).await.unwrap().relays.contains(&shared));
    }

    #[tokio::test]
    async fn exit_flags_follow_default_route_approval() {
        // AD-1/AD-2: approving `0.0.0.0/0` makes the device an exit — visible as
        // `self_exit` in its own config and `exit` on its peer entry elsewhere;
        // deleting the route revokes both. Covers the SQL path end to end.
        let s = SqlStore::connect("sqlite:file:memdb_exit?mode=memory&cache=shared")
            .await
            .unwrap();
        let net = s.create_network("home").await.unwrap();
        let inv = s.create_invite(&net.id, None, None).await.unwrap();
        let (exit_dev, _) = s.enroll(&inv.code, "exit", "6219b8ea7c0a1c302822dbcfe356b4f86d9745391e2d30db8356fc7fd7aae4a2", 1000).await.unwrap();
        let (client, _) = s.enroll(&inv.code, "laptop", "2e92a4cccb0d9b15ec77237ee16ec658ac4d45055818ec30cdc3dbf0c3db8092", 1000).await.unwrap();

        async fn peer_exit(s: &SqlStore, client_id: &str) -> bool {
            s.device_config(client_id)
                .await
                .unwrap()
                .peers
                .iter()
                .find(|p| p.wg_public_key == "6219b8ea7c0a1c302822dbcfe356b4f86d9745391e2d30db8356fc7fd7aae4a2")
                .map(|p| p.exit)
                .unwrap_or(false)
        }
        assert!(!s.device_config(&exit_dev.id).await.unwrap().self_exit);
        assert!(!peer_exit(&s, &client.id).await);

        let route = s.advertise_route(&exit_dev.id, "0.0.0.0/0").await.unwrap();
        assert!(!s.device_config(&exit_dev.id).await.unwrap().self_exit); // unapproved
        assert!(!peer_exit(&s, &client.id).await);

        s.approve_route(&route.id).await.unwrap();
        assert!(s.device_config(&exit_dev.id).await.unwrap().self_exit);
        assert!(peer_exit(&s, &client.id).await);
        // The default prefix remains in allowed_ips (old-node compatibility).
        let cfg = s.device_config(&client.id).await.unwrap();
        let p = cfg.peers.iter().find(|p| p.wg_public_key == "6219b8ea7c0a1c302822dbcfe356b4f86d9745391e2d30db8356fc7fd7aae4a2").unwrap();
        assert!(p.allowed_ips.iter().any(|a| a == "0.0.0.0/0"));

        s.delete_route(&route.id).await.unwrap();
        assert!(!s.device_config(&exit_dev.id).await.unwrap().self_exit);
        assert!(!peer_exit(&s, &client.id).await);
    }

    #[tokio::test]
    async fn invite_validation_persisted() {
        let s = SqlStore::connect("sqlite:file:memdb_inv?mode=memory&cache=shared")
            .await
            .unwrap();
        let net = s.create_network("n").await.unwrap();
        let inv = s.create_invite(&net.id, None, Some(1)).await.unwrap();
        assert!(s.enroll(&inv.code, "a", "3ebb1c99b12b77463e97c3a0f206e4fd46176cd1b8e183816a67338c04b25e5b", 1000).await.is_ok());
        // use limit hit
        assert!(matches!(
            s.enroll(&inv.code, "b", "74fec0c33e96ab90ac88666979207a50a6ea7b9b3eea6ec0e8b916d64c0a0706", 1000).await,
            Err(SqlStoreError::InvalidInvite)
        ));
        // unknown invite
        assert!(matches!(
            s.enroll("nope", "c", "ad9cdbefb70da610b07dcc613934052a0996f5c0da58a2d9632ec966361de506", 1000).await,
            Err(SqlStoreError::InvalidInvite)
        ));
    }
}

#[cfg(test)]
#[path = "integrity_tests.rs"]
mod integrity_tests;
