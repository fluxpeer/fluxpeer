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
use sqlx::Row;

#[derive(Debug, thiserror::Error)]
pub enum SqlStoreError {
    #[error("network not found")]
    NetworkNotFound,
    #[error("device not found")]
    DeviceNotFound,
    #[error("relay not found")]
    RelayNotFound,
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
    Db(sqlx::Error),
}

impl From<sqlx::Error> for SqlStoreError {
    fn from(error: sqlx::Error) -> Self {
        // Log here because login and watch callers can deliberately hide errors
        // from clients. Never include query parameters or credentials.
        if matches!(error, sqlx::Error::PoolTimedOut) {
            tracing::error!(timeout_ms = 5000, "control database pool acquire timed out");
        }
        Self::Db(error)
    }
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

    #[cfg(test)]
    pub(crate) fn watcher_count(&self, id: &str) -> usize {
        self.epoch_tx.lock().get(id).map_or(0, watch::Sender::receiver_count)
    }

    /// The network a device belongs to (if any).
    pub async fn network_of(&self, device_id: &str) -> Result<Option<String>> {
        Ok(db::get_device(&self.pool, device_id).await?.map(|d| d.network_id))
    }

    async fn next_seq(&self) -> Result<i64> {
        crate::contention::retry("next_seq", true, || self.next_seq_once()).await
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
        crate::contention::retry("create_invite", false, || self.create_invite_once(network_id, expires_at, max_uses)).await
    }

    async fn create_invite_once(
        &self,
        network_id: &str,
        expires_at: Option<i64>,
        max_uses: Option<u32>,
    ) -> Result<Invite> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        if db::get_network(&mut *tx, network_id).await?.is_none() {
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
        db::insert_invite(&mut *tx, &invite).await?;
        tx.commit().await?;
        Ok(invite)
    }

    /// Serialize lifecycle changes with enrollment and import across processes.
    pub async fn delete_network(&self, network_id: &str) -> Result<()> {
        crate::contention::retry("delete_network", false, || self.delete_network_once(network_id)).await
    }

    async fn delete_network_once(&self, network_id: &str) -> Result<()> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        let net = db::get_network(&mut *tx, network_id).await?.ok_or(SqlStoreError::NetworkNotFound)?;
        sqlx::query("UPDATE device SET status = 'revoked', auth_token = NULL, address_v4 = NULL, address_v6 = NULL WHERE network_id = $1")
            .bind(network_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM device_stats WHERE device_id IN (SELECT id FROM device WHERE network_id = $1)")
            .bind(network_id).execute(&mut *tx).await?;
        for query in ["DELETE FROM invite WHERE network_id = $1", "DELETE FROM route WHERE network_id = $1", "DELETE FROM relay WHERE network_id = $1"] {
            sqlx::query(query).bind(network_id).execute(&mut *tx).await?;
        }
        db::bump_network_epoch(&mut *tx, network_id).await?;
        sqlx::query("DELETE FROM network WHERE id = $1").bind(network_id).execute(&mut *tx).await?;
        tx.commit().await?;
        // Publish only after commit, then close the deleted network's broadcaster.
        if let Some(sender) = self.epoch_tx.lock().remove(network_id) {
            sender.send_replace(net.config_epoch.saturating_add(1));
        }
        Ok(())
    }

    pub async fn revoke_invite(&self, network_id: &str, code: &str) -> Result<()> {
        crate::contention::retry("revoke_invite", false, || self.revoke_invite_once(network_id, code)).await
    }

    async fn revoke_invite_once(&self, network_id: &str, code: &str) -> Result<()> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        if db::get_network(&mut *tx, network_id).await?.is_none() { return Err(SqlStoreError::NetworkNotFound); }
        let affected = sqlx::query("DELETE FROM invite WHERE network_id = $1 AND code = $2")
            .bind(network_id).bind(code).execute(&mut *tx).await?.rows_affected();
        if affected == 0 { return Err(SqlStoreError::InvalidInvite); }
        tx.commit().await?;
        Ok(())
    }

    pub(crate) async fn token_network(&self, token: &str) -> Result<Option<String>> {
        Ok(sqlx::query_scalar("SELECT network_id FROM device WHERE auth_token = $1 AND status = 'active' AND EXISTS (SELECT 1 FROM network WHERE network.id = device.network_id) LIMIT 1")
            .bind(token).fetch_optional(&self.pool).await?)
    }

    pub(crate) async fn resolve(&self, network_id: &str, name: &str) -> Result<Device> {
        self.list_devices(network_id).await?.into_iter()
            .find(|device| device.name == name && device.status == DeviceStatus::Active)
            .ok_or(SqlStoreError::DeviceNotFound)
    }

    /// Redeem an invite and enroll a device. Returns the device AND a freshly-issued
    /// per-device auth token — the device's only credential for its own config read /
    /// endpoint writes (so a guessable `dev-N` id is no longer authority). The token
    /// is returned ONCE here and never echoed by any other endpoint.
    pub async fn enroll(&self, invite_code: &str, name: &str, wg_public_key: &str, now: i64) -> Result<(Device, String)> {
        let key = fluxpeer_sdk::key::normalize(wg_public_key).ok_or(SqlStoreError::InvalidKey)?;
        crate::contention::retry("enroll", true, || self.enroll_once(invite_code, name, &key, now)).await
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

    /// Distinguish a valid token for another device from an unauthenticated caller.
    pub(crate) async fn has_device_token(&self, token: &str) -> Result<bool> {
        let id = sqlx::query_scalar::<_, String>("SELECT id FROM device WHERE auth_token = $1 AND status = 'active' LIMIT 1")
            .bind(token).fetch_optional(&self.pool).await?;
        Ok(id.is_some())
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
        crate::contention::retry("import_devices", true, || self.import_once(network_id, &devices, &keys)).await
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
        if let Err(error) = db::insert_audit(&self.pool, ts, actor, action).await {
            // Audit remains best-effort, but database failure must be visible.
            crate::internal_error(error.into());
        }
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
        crate::contention::retry("revoke_device", true, || self.revoke_device_once(device_id)).await
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
        crate::contention::retry("advertise_route", false, || self.advertise_route_once(device_id, prefix)).await
    }

    async fn advertise_route_once(&self, device_id: &str, prefix: &str) -> Result<Route> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        let dev = db::get_device(&mut *tx, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        if dev.status != DeviceStatus::Active || db::get_network(&mut *tx, &dev.network_id).await?.is_none() { return Err(SqlStoreError::DeviceNotFound); }
        let route = Route {
            id: format!("route-{}", crate::integrity::next(&mut tx).await?),
            network_id: dev.network_id,
            device_id: device_id.to_string(),
            prefix: normalize_prefix(prefix).ok_or(SqlStoreError::InvalidPrefix)?,
            approved: false,
        };
        db::insert_route(&mut *tx, &route).await?;
        tx.commit().await?;
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

    /// Lock only the active device row, also conflicting with revoke/cascade.
    /// A no-op UPDATE is portable to PostgreSQL and SQLite and obtains the write
    /// lock before any read, without touching the global entity sequence.
    async fn lock_active_device(conn: &mut sqlx::AnyConnection, device_id: &str) -> Result<()> {
        let locked = sqlx::query("UPDATE device SET status = status WHERE id = $1 AND status = 'active' AND EXISTS (SELECT 1 FROM network WHERE network.id = device.network_id)")
            .bind(device_id).execute(conn).await?.rows_affected();
        if locked != 1 { return Err(SqlStoreError::DeviceNotFound); }
        Ok(())
    }

    /// Record a node-reported traffic stats sample (cumulative rx/tx + per-peer blob).
    pub async fn report_stats(&self, device_id: &str, rx: i64, tx: i64, peers_json: &str, at: i64) -> Result<()> {
        crate::contention::retry("report_stats", false, || self.report_stats_once(device_id, rx, tx, peers_json, at)).await
    }

    async fn report_stats_once(&self, device_id: &str, rx: i64, tx: i64, peers_json: &str, at: i64) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        Self::lock_active_device(&mut transaction, device_id).await?;
        db::upsert_device_stats(&mut *transaction, device_id, rx, tx, peers_json, at).await?;
        transaction.commit().await?;
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
        self.register_relay_authenticated(region, url, network_id, anytls, stun_url, (node_id, None)).await
    }

    pub async fn register_relay_authenticated(
        &self,
        region: &str,
        url: &str,
        network_id: Option<String>,
        anytls: bool,
        stun_url: Option<String>,
        identity: (Option<String>, Option<String>),
    ) -> Result<RelayNode> {
        crate::contention::retry("register_relay_authenticated", false, || self.register_relay_authenticated_once(region, url, network_id.clone(), anytls, stun_url.clone(), identity.clone())).await
    }

    async fn register_relay_authenticated_once(
        &self,
        region: &str,
        url: &str,
        network_id: Option<String>,
        anytls: bool,
        stun_url: Option<String>,
        identity: (Option<String>, Option<String>),
    ) -> Result<RelayNode> {
        let (node_id, public_key) = identity;
        let mut tx = crate::integrity::begin(&self.pool).await?;
        if let Some(id) = &network_id && db::get_network(&mut *tx, id).await?.is_none() { return Err(SqlStoreError::NetworkNotFound); }
        let relay = RelayNode {
            id: format!("relay-{}", crate::integrity::next(&mut tx).await?),
            region: region.to_string(),
            url: url.to_string(),
            network_id,
            anytls,
            stun_url: stun_url.or_else(|| Some(url.to_string())),
            node_id,
            public_key,
        };
        db::insert_relay(&mut *tx, &relay).await?;
        let networks: Vec<String> = sqlx::query_scalar("SELECT id FROM network WHERE CAST($1 AS TEXT) IS NULL OR id = $1")
            .bind(&relay.network_id).fetch_all(&mut *tx).await?;
        for id in &networks { db::bump_network_epoch(&mut *tx, id).await?; }
        tx.commit().await?;
        for id in networks { self.notify(&id).await; }
        Ok(relay)
    }

    pub async fn update_relay(&self, relay: RelayNode) -> Result<RelayNode> {
        crate::contention::retry("update_relay", false, || self.update_relay_once(relay.clone())).await
    }

    async fn update_relay_once(&self, relay: RelayNode) -> Result<RelayNode> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        if let Some(scope) = &relay.network_id && db::get_network(&mut *tx, scope).await?.is_none() { return Err(SqlStoreError::NetworkNotFound); }
        let old = sqlx::query("SELECT network_id FROM relay WHERE id = $1").bind(&relay.id)
            .fetch_optional(&mut *tx).await?.ok_or(SqlStoreError::RelayNotFound)?;
        let old_scope: Option<String> = old.try_get("network_id")?;
        sqlx::query("UPDATE relay SET region = $2, url = $3, network_id = $4, anytls = $5, stun_url = $6, node_id = $7, public_key = $8 WHERE id = $1")
            .bind(&relay.id).bind(&relay.region).bind(&relay.url).bind(&relay.network_id)
            .bind(i64::from(relay.anytls)).bind(&relay.stun_url).bind(&relay.node_id).bind(&relay.public_key).execute(&mut *tx).await?;
        let networks: Vec<String> = sqlx::query_scalar("SELECT id FROM network WHERE CAST($1 AS TEXT) IS NULL OR CAST($2 AS TEXT) IS NULL OR id = $1 OR id = $2")
            .bind(&old_scope).bind(&relay.network_id).fetch_all(&mut *tx).await?;
        for id in &networks { db::bump_network_epoch(&mut *tx, id).await?; }
        tx.commit().await?;
        for id in networks { self.notify(&id).await; }
        Ok(relay)
    }

    /// Relays usable by a network: those scoped to it plus shared/official ones.
    pub async fn list_relays(&self, network_id: &str) -> Result<Vec<RelayNode>> {
        Ok(db::list_relays(&self.pool, network_id).await?)
    }

    /// A device reports its current candidate endpoints; peers pick them up on
    /// their next config-pull/push (epoch bumped to notify watchers).
    pub async fn set_endpoints(&self, device_id: &str, endpoints: &[String]) -> Result<()> {
        crate::contention::retry("set_endpoints", false, || self.set_endpoints_once(device_id, endpoints)).await
    }

    async fn set_endpoints_once(&self, device_id: &str, endpoints: &[String]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::lock_active_device(&mut tx, device_id).await?;
        let device = db::get_device(&mut *tx, device_id)
            .await?
            .ok_or(SqlStoreError::DeviceNotFound)?;
        db::set_device_endpoints(&mut *tx, device_id, endpoints).await?;
        db::bump_network_epoch(&mut *tx, &device.network_id).await?;
        tx.commit().await?;
        self.notify(&device.network_id).await;
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
    async fn relay_mutations_bump_only_affected_epochs_notify_and_rollback_atomically() {
        let url = "sqlite:file:relay_epoch_sync?mode=memory&cache=shared";
        let s = SqlStore::connect(url).await.unwrap();
        let a = s.create_network("a").await.unwrap(); let b = s.create_network("b").await.unwrap();
        let c = s.create_network("c").await.unwrap();
        let mut wa = s.subscribe(&a.id); let mut wb = s.subscribe(&b.id); let mut wc = s.subscribe(&c.id);
        let mut relay = s.register_relay_authenticated("eu", "192.0.2.1:443", Some(a.id.clone()), true, None, (Some("edge".into()), Some("11".repeat(32)))).await.unwrap();
        assert_eq!(*wa.borrow_and_update(), 1); assert!(!wb.has_changed().unwrap()); assert!(!wc.has_changed().unwrap());
        relay.network_id = Some(b.id.clone()); relay.url = "192.0.2.2:443".into(); relay.public_key = Some("22".repeat(32));
        s.update_relay(relay.clone()).await.unwrap();
        assert_eq!(*wa.borrow_and_update(), 2); assert_eq!(*wb.borrow_and_update(), 1); assert!(!wc.has_changed().unwrap());
        assert!(s.list_relays(&a.id).await.unwrap().is_empty());
        let reopened = SqlStore::connect(url).await.unwrap();
        assert_eq!(reopened.list_relays(&b.id).await.unwrap(), [relay.clone()]);
        relay.network_id = None;
        s.update_relay(relay.clone()).await.unwrap();
        assert_eq!(*wa.borrow_and_update(), 3); assert_eq!(*wb.borrow_and_update(), 2); assert_eq!(*wc.borrow_and_update(), 1);
        relay.network_id = Some(c.id.clone());
        s.update_relay(relay.clone()).await.unwrap(); // shared -> scoped must also invalidate networks losing visibility
        assert_eq!(*wa.borrow_and_update(), 4); assert_eq!(*wb.borrow_and_update(), 3); assert_eq!(*wc.borrow_and_update(), 2);
        let saved = relay.clone();
        sqlx::query("CREATE TRIGGER reject_relay_epoch BEFORE UPDATE OF config_epoch ON network BEGIN SELECT RAISE(ABORT, 'injected epoch failure'); END")
            .execute(&s.pool).await.unwrap();
        relay.url = "192.0.2.99:443".into();
        assert!(s.update_relay(relay).await.is_err());
        assert!(s.register_relay("bad", "192.0.2.99:443", None, false, None, None).await.is_err());
        assert_eq!(reopened.list_relays(&c.id).await.unwrap(), [saved]);
        assert_eq!(db::get_network(&s.pool, &c.id).await.unwrap().unwrap().config_epoch, 2);
        assert!(!wa.has_changed().unwrap()); assert!(!wb.has_changed().unwrap()); assert!(!wc.has_changed().unwrap());
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

#[cfg(test)]
#[path = "sql_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "sqlite_contention_tests.rs"]
mod contention_tests;
