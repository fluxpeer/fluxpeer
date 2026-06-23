//! In-memory coordination store. PostgreSQL/SeaORM persistence replaces the
//! backing maps later; the method surface is the contract. Logic is kept free of
//! HTTP so it can be unit-tested directly (see tests below).
//!
//! Implements the MVP coordination loop: create network → generate
//! invite → enroll device (allocate stable IP) → list → revoke. Peer-level
//! revocation bumps the network `config_epoch` so clients resync.

use crate::domain::{Device, DeviceConfig, DeviceStatus, ImportDevice, ImportResult, Invite, Network, PeerConfig, RelayNode, Route};
use crate::ipam::{Ipam, IpamError};
use parking_lot::Mutex;
use rand::RngCore;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    NetworkNotFound,
    DeviceNotFound,
    RouteNotFound,
    InvalidInvite,
    PoolExhausted,
}

struct Inner {
    networks: HashMap<String, Network>,
    devices: HashMap<String, Device>,
    invites: HashMap<String, Invite>,
    ipams: HashMap<String, Ipam>,
    /// Subnet routes advertised by devices, keyed by route id.
    routes: HashMap<String, Route>,
    /// Registered relay nodes, keyed by relay id.
    relays: HashMap<String, RelayNode>,
    /// Device-reported candidate endpoints for disco, keyed by device id.
    endpoints: HashMap<String, Vec<String>>,
    /// Per-network config-epoch broadcaster for WS push.
    epoch_tx: HashMap<String, watch::Sender<u64>>,
}

/// Bump a network's config epoch and notify watchers.
fn bump_epoch(inner: &mut Inner, network_id: &str) {
    let epoch = match inner.networks.get_mut(network_id) {
        Some(net) => {
            net.config_epoch += 1;
            net.config_epoch
        }
        None => return,
    };
    if let Some(tx) = inner.epoch_tx.get(network_id) {
        let _ = tx.send(epoch);
    }
}

pub struct Store {
    inner: Mutex<Inner>,
    seq: AtomicU64,
    net_index: AtomicU64,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                networks: HashMap::new(),
                devices: HashMap::new(),
                invites: HashMap::new(),
                ipams: HashMap::new(),
                routes: HashMap::new(),
                relays: HashMap::new(),
                endpoints: HashMap::new(),
                epoch_tx: HashMap::new(),
            }),
            seq: AtomicU64::new(1),
            net_index: AtomicU64::new(0),
        }
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Create a network, deriving its overlay pools from the self-host default
    /// CGNAT block + a ULA /48. The ULA prefix is `fd` followed by a CSPRNG-random
    /// 40-bit Global ID, per RFC 4193 (so two independently created networks are
    /// vanishingly unlikely to collide).
    pub fn create_network(&self, name: &str) -> Network {
        let idx = self.net_index.fetch_add(1, Ordering::Relaxed);
        let octet = (idx % 200) as u8 + 16; // keep inside the 100.72/16 overlay range

        // RFC 4193 ULA /48 = 0xfd (8 bits) + a random 40-bit Global ID.
        let global_id = rand::rng().next_u64() & 0xff_ffff_ffff; // low 40 bits
        let ula = [
            0xfd00 | ((global_id >> 32) as u16 & 0x00ff),
            (global_id >> 16) as u16,
            global_id as u16,
        ];

        let net = Network {
            id: format!("net-{}", self.next_seq()),
            name: name.to_string(),
            ipv4_pool: format!("100.72.{octet}.0/24"),
            ipv6_ula: format!("{:04x}:{:04x}:{:04x}::/48", ula[0], ula[1], ula[2]),
            config_epoch: 0,
        };
        let ipam = Ipam::new(Ipv4Addr::new(100, 72, octet, 0), ula);
        let mut g = self.inner.lock();
        g.ipams.insert(net.id.clone(), ipam);
        g.epoch_tx.insert(net.id.clone(), watch::channel(0).0);
        g.networks.insert(net.id.clone(), net.clone());
        net
    }

    pub fn list_networks(&self) -> Vec<Network> {
        self.inner.lock().networks.values().cloned().collect()
    }

    /// Generate an enrollment invite for a network.
    pub fn create_invite(
        &self,
        network_id: &str,
        expires_at: Option<i64>,
        max_uses: Option<u32>,
    ) -> Result<Invite, StoreError> {
        let code = crate::auth::random_hex(16); // CSPRNG: invite codes are bearer credentials
        let mut g = self.inner.lock();
        if !g.networks.contains_key(network_id) {
            return Err(StoreError::NetworkNotFound);
        }
        let invite = Invite {
            code: code.clone(),
            network_id: network_id.to_string(),
            expires_at,
            max_uses,
            uses: 0,
        };
        g.invites.insert(code, invite.clone());
        Ok(invite)
    }

    /// Redeem an invite and enroll a device: allocates a stable dual-stack
    /// address, increments invite use, bumps the network epoch.
    pub fn enroll(&self, invite_code: &str, name: &str, wg_public_key: &str, now: i64) -> Result<Device, StoreError> {
        let mut g = self.inner.lock();
        let invite = g.invites.get(invite_code).cloned().ok_or(StoreError::InvalidInvite)?;
        if !invite.is_redeemable(now) {
            return Err(StoreError::InvalidInvite);
        }
        let network_id = invite.network_id.clone();
        let (v4, v6) = {
            let ipam = g.ipams.get_mut(&network_id).ok_or(StoreError::NetworkNotFound)?;
            ipam.allocate(wg_public_key).map_err(|e| match e {
                IpamError::PoolExhausted => StoreError::PoolExhausted,
            })?
        };
        let device = Device {
            id: format!("dev-{}", self.next_seq()),
            network_id: network_id.clone(),
            name: name.to_string(),
            wg_public_key: wg_public_key.to_string(),
            address_v4: Some(v4.to_string()),
            address_v6: Some(v6.to_string()),
            status: DeviceStatus::Active,
        };
        if let Some(inv) = g.invites.get_mut(invite_code) {
            inv.uses += 1;
        }
        g.devices.insert(device.id.clone(), device.clone());
        bump_epoch(&mut g, &network_id);
        Ok(device)
    }

    /// Batch-register devices parsed from a wg.conf (`fp import`). Fixed addresses
    /// are preserved verbatim (and their host octet reserved so future auto-enroll
    /// won't collide); existing public keys are skipped (idempotent). One epoch
    /// bump for the whole batch. Admin-gated at the HTTP layer.
    pub fn import_devices(&self, network_id: &str, devices: &[ImportDevice]) -> Result<ImportResult, StoreError> {
        let mut g = self.inner.lock();
        if !g.networks.contains_key(network_id) {
            return Err(StoreError::NetworkNotFound);
        }
        let mut seen: std::collections::HashSet<String> = g
            .devices
            .values()
            .filter(|d| d.network_id == network_id)
            .map(|d| d.wg_public_key.clone())
            .collect();
        let mut created = Vec::new();
        let mut skipped = Vec::new();
        for d in devices {
            if d.wg_public_key.is_empty() || !seen.insert(d.wg_public_key.clone()) {
                skipped.push(d.wg_public_key.clone());
                continue;
            }
            if let Some(host) = d
                .address_v4
                .as_deref()
                .and_then(|a| a.parse::<Ipv4Addr>().ok())
                .map(|ip| ip.octets()[3])
                && let Some(ipam) = g.ipams.get_mut(network_id)
            {
                let _ = ipam.reserve(&d.wg_public_key, host);
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
            if !d.endpoints.is_empty() {
                g.endpoints.insert(device.id.clone(), d.endpoints.clone());
            }
            g.devices.insert(device.id.clone(), device.clone());
            created.push(device);
        }
        if !created.is_empty() {
            bump_epoch(&mut g, network_id);
        }
        Ok(ImportResult { created, skipped })
    }

    pub fn list_devices(&self, network_id: &str) -> Result<Vec<Device>, StoreError> {
        let g = self.inner.lock();
        if !g.networks.contains_key(network_id) {
            return Err(StoreError::NetworkNotFound);
        }
        Ok(g.devices
            .values()
            .filter(|d| d.network_id == network_id)
            .cloned()
            .collect())
    }

    /// Revoke a device: mark revoked, recycle its address, bump the
    /// network epoch so peers stop accepting it on next sync.
    pub fn revoke_device(&self, device_id: &str) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let device = g.devices.get(device_id).cloned().ok_or(StoreError::DeviceNotFound)?;
        if let Some(ipam) = g.ipams.get_mut(&device.network_id) {
            ipam.recycle(&device.wg_public_key);
        }
        if let Some(d) = g.devices.get_mut(device_id) {
            d.status = DeviceStatus::Revoked;
        }
        bump_epoch(&mut g, &device.network_id);
        Ok(())
    }

    /// A device reports its current candidate endpoints; bumps the epoch
    /// so peers pick them up.
    pub fn set_endpoints(&self, device_id: &str, endpoints: &[String]) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let device = g.devices.get(device_id).cloned().ok_or(StoreError::DeviceNotFound)?;
        g.endpoints.insert(device_id.to_string(), endpoints.to_vec());
        bump_epoch(&mut g, &device.network_id);
        Ok(())
    }

    /// Advertise a subnet route from a device (Subnet Router). Created
    /// unapproved; has no effect on config until approved.
    pub fn advertise_route(&self, device_id: &str, prefix: &str) -> Result<Route, StoreError> {
        let mut g = self.inner.lock();
        let dev = g.devices.get(device_id).cloned().ok_or(StoreError::DeviceNotFound)?;
        let route = Route {
            id: format!("route-{}", self.next_seq()),
            network_id: dev.network_id,
            device_id: device_id.to_string(),
            prefix: prefix.to_string(),
            approved: false,
        };
        g.routes.insert(route.id.clone(), route.clone());
        Ok(route)
    }

    /// Approve a subnet route: now distributed in peer allowed-ips; bumps
    /// the network epoch so peers pick it up.
    pub fn approve_route(&self, route_id: &str) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        let network_id = match g.routes.get_mut(route_id) {
            Some(r) => {
                r.approved = true;
                r.network_id.clone()
            }
            None => return Err(StoreError::RouteNotFound),
        };
        bump_epoch(&mut g, &network_id);
        Ok(())
    }

    /// Register a relay node. `network_id = None` = shared/official.
    /// `stun_url` defaults to `url` (the relay doubles as STUN).
    pub fn register_relay(
        &self,
        region: &str,
        url: &str,
        network_id: Option<String>,
        anytls: bool,
        stun_url: Option<String>,
    ) -> RelayNode {
        let relay = RelayNode {
            id: format!("relay-{}", self.next_seq()),
            region: region.to_string(),
            url: url.to_string(),
            network_id,
            anytls,
            stun_url: stun_url.or_else(|| Some(url.to_string())),
        };
        self.inner.lock().relays.insert(relay.id.clone(), relay.clone());
        relay
    }

    /// Relays usable by a network: those scoped to it plus shared/official ones.
    pub fn list_relays(&self, network_id: &str) -> Vec<RelayNode> {
        self.inner
            .lock()
            .relays
            .values()
            .filter(|r| r.network_id.as_deref() == Some(network_id) || r.network_id.is_none())
            .cloned()
            .collect()
    }

    /// MagicDNS: resolve a device name within a network to its overlay
    /// IPv4 address (case-insensitive; active devices only).
    pub fn resolve(&self, network_id: &str, name: &str) -> Option<String> {
        let g = self.inner.lock();
        g.devices
            .values()
            .find(|d| {
                d.network_id == network_id && d.status == DeviceStatus::Active && d.name.eq_ignore_ascii_case(name)
            })
            .and_then(|d| d.address_v4.clone())
    }

    /// Subscribe to a network's config-epoch changes (for WS push).
    pub fn subscribe(&self, network_id: &str) -> Option<watch::Receiver<u64>> {
        self.inner.lock().epoch_tx.get(network_id).map(|tx| tx.subscribe())
    }

    /// The network a device belongs to, if it exists.
    pub fn network_id_of_device(&self, device_id: &str) -> Option<String> {
        self.inner.lock().devices.get(device_id).map(|d| d.network_id.clone())
    }

    pub fn network_epoch(&self, network_id: &str) -> Option<u64> {
        self.inner.lock().networks.get(network_id).map(|n| n.config_epoch)
    }

    /// The config a device pulls: its own addresses, the network epoch, and the
    /// set of OTHER active peers (pubkey + allowed-ips). A revoked device is cut
    /// off — it gets `DeviceNotFound`.
    pub fn device_config(&self, device_id: &str) -> Result<DeviceConfig, StoreError> {
        let g = self.inner.lock();
        let me = g.devices.get(device_id).ok_or(StoreError::DeviceNotFound)?;
        if me.status != DeviceStatus::Active {
            return Err(StoreError::DeviceNotFound);
        }
        let config_epoch = g.networks.get(&me.network_id).map(|n| n.config_epoch).unwrap_or(0);
        // Approved subnet routes in this network, as (advertising device, prefix).
        let approved: Vec<(String, String)> = g
            .routes
            .values()
            .filter(|r| r.network_id == me.network_id && r.approved)
            .map(|r| (r.device_id.clone(), r.prefix.clone()))
            .collect();
        let peers = g
            .devices
            .values()
            .filter(|d| d.network_id == me.network_id && d.id != me.id && d.status == DeviceStatus::Active)
            .map(|d| {
                let mut allowed_ips = Vec::new();
                if let Some(v4) = &d.address_v4 {
                    allowed_ips.push(format!("{v4}/32"));
                }
                if let Some(v6) = &d.address_v6 {
                    allowed_ips.push(format!("{v6}/128"));
                }
                // Subnet Router: this peer also routes its approved prefixes.
                for (did, prefix) in &approved {
                    if did == &d.id {
                        allowed_ips.push(prefix.clone());
                    }
                }
                PeerConfig {
                    wg_public_key: d.wg_public_key.clone(),
                    allowed_ips,
                    endpoints: g.endpoints.get(&d.id).cloned().unwrap_or_default(),
                }
            })
            .collect();
        // Relay directory for this network (scoped + shared/official); same lock.
        let relays = g
            .relays
            .values()
            .filter(|r| r.network_id.as_deref() == Some(me.network_id.as_str()) || r.network_id.is_none())
            .cloned()
            .collect();
        Ok(DeviceConfig {
            network_id: me.network_id.clone(),
            config_epoch,
            address_v4: me.address_v4.clone(),
            address_v6: me.address_v6.clone(),
            peers,
            relays,
            mtu: None,
            dns: Vec::new(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn full_enroll_loop() {
        let s = Store::new();
        let net = s.create_network("home");
        assert_eq!(s.network_epoch(&net.id), Some(0));

        let inv = s.create_invite(&net.id, None, Some(2)).unwrap();
        let dev = s.enroll(&inv.code, "laptop", "pubkey-A", 1000).unwrap();

        assert_eq!(dev.network_id, net.id);
        assert_eq!(dev.address_v4.as_deref(), Some("100.72.16.100"));
        assert_eq!(dev.status, DeviceStatus::Active);
        // enrolling bumped the epoch
        assert_eq!(s.network_epoch(&net.id), Some(1));
        assert_eq!(s.list_devices(&net.id).unwrap().len(), 1);
    }

    #[test]
    fn import_preserves_fixed_addresses_is_idempotent_and_reserves() {
        let s = Store::new();
        let net = s.create_network("home");
        let dev = |name: &str, key: &str, v4: &str| ImportDevice {
            name: name.into(),
            wg_public_key: key.into(),
            address_v4: Some(v4.into()),
            address_v6: None,
            endpoints: vec![],
        };

        // Import a hub + two spokes with fixed addresses straight from a wg.conf.
        let r = s
            .import_devices(
                &net.id,
                &[
                    dev("hub", "k-hub", "10.0.0.1"),
                    dev("laptop", "k-laptop", "10.0.0.5"),
                    // host octet.100 falls inside the auto-allocation range, so
                    // reserving it forces the next enroll off.100.
                    dev("phone", "k-phone", "10.0.0.100"),
                ],
            )
            .unwrap();
        assert_eq!(r.created.len(), 3);
        assert!(r.skipped.is_empty());
        // Addresses are preserved verbatim (not re-allocated into the.100 range).
        let laptop = r.created.iter().find(|d| d.name == "laptop").unwrap();
        assert_eq!(laptop.address_v4.as_deref(), Some("10.0.0.5"));
        assert_eq!(s.list_devices(&net.id).unwrap().len(), 3);
        // The whole batch is a single epoch bump.
        assert_eq!(s.network_epoch(&net.id), Some(1));

        // Re-importing the same keys is idempotent (skipped, no new epoch).
        let r2 = s
            .import_devices(&net.id, &[dev("laptop-again", "k-laptop", "10.0.0.5")])
            .unwrap();
        assert!(r2.created.is_empty());
        assert_eq!(r2.skipped, vec!["k-laptop".to_string()]);
        assert_eq!(s.network_epoch(&net.id), Some(1));

        // A subsequent auto-enroll skips the reserved.100 host (imported phone),
        // proving import reserved the octet in IPAM — it lands on.101.
        let inv = s.create_invite(&net.id, None, None).unwrap();
        let new = s.enroll(&inv.code, "fresh", "k-fresh", 1000).unwrap();
        assert_eq!(new.address_v4.as_deref(), Some("100.72.16.101"));
    }

    #[test]
    fn import_into_missing_network_errs() {
        let s = Store::new();
        assert_eq!(s.import_devices("net-nope", &[]).unwrap_err(), StoreError::NetworkNotFound);
    }

    #[test]
    fn invite_use_limit_enforced() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, None, Some(1)).unwrap();
        assert!(s.enroll(&inv.code, "d1", "k1", 1000).is_ok());
        assert_eq!(s.enroll(&inv.code, "d2", "k2", 1000), Err(StoreError::InvalidInvite));
    }

    #[test]
    fn expired_invite_rejected() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, Some(500), None).unwrap();
        assert_eq!(s.enroll(&inv.code, "d", "k", 1000), Err(StoreError::InvalidInvite));
    }

    #[test]
    fn revoke_recycles_address_and_bumps_epoch() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, None, None).unwrap();
        let d1 = s.enroll(&inv.code, "d1", "k1", 1000).unwrap();
        let epoch_before = s.network_epoch(&net.id).unwrap();

        s.revoke_device(&d1.id).unwrap();
        assert_eq!(s.network_epoch(&net.id), Some(epoch_before + 1));

        // recycled address is reused by the next enrollee
        let d2 = s.enroll(&inv.code, "d2", "k2", 1000).unwrap();
        assert_eq!(d2.address_v4, d1.address_v4);
    }

    #[test]
    fn peer_config_lists_other_active_peers_with_allowed_ips() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, None, None).unwrap();
        let d1 = s.enroll(&inv.code, "d1", "k1", 1000).unwrap();
        let d2 = s.enroll(&inv.code, "d2", "k2", 1000).unwrap();

        let cfg = s.device_config(&d1.id).unwrap();
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].wg_public_key, "k2");
        let v4 = d2.address_v4.unwrap();
        assert!(cfg.peers[0].allowed_ips.contains(&format!("{v4}/32")));
    }

    #[test]
    fn revoked_peer_disappears_and_revoked_device_is_cut_off() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, None, None).unwrap();
        let d1 = s.enroll(&inv.code, "d1", "k1", 1000).unwrap();
        let d2 = s.enroll(&inv.code, "d2", "k2", 1000).unwrap();

        s.revoke_device(&d2.id).unwrap();
        assert!(s.device_config(&d1.id).unwrap().peers.is_empty());
        assert_eq!(s.device_config(&d2.id).unwrap_err(), StoreError::DeviceNotFound);
    }

    #[test]
    fn invite_for_missing_network_fails() {
        let s = Store::new();
        assert_eq!(
            s.create_invite("net-nope", None, None).unwrap_err(),
            StoreError::NetworkNotFound
        );
    }

    #[test]
    fn subnet_route_appears_in_peer_config_only_when_approved() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, None, None).unwrap();
        let router_dev = s.enroll(&inv.code, "router", "kr", 1000).unwrap();
        let other = s.enroll(&inv.code, "laptop", "kl", 1000).unwrap();

        let route = s.advertise_route(&router_dev.id, "192.168.1.0/24").unwrap();
        let has_prefix = |s: &Store| {
            s.device_config(&other.id)
                .unwrap()
                .peers
                .iter()
                .find(|p| p.wg_public_key == "kr")
                .map(|p| p.allowed_ips.iter().any(|a| a == "192.168.1.0/24"))
                .unwrap_or(false)
        };
        assert!(!has_prefix(&s)); // unapproved
        s.approve_route(&route.id).unwrap();
        assert!(has_prefix(&s)); // approved → distributed
    }

    #[test]
    fn relay_directory_scopes_shared_and_network_relays() {
        let s = Store::new();
        let net_a = s.create_network("a");
        let net_b = s.create_network("b");
        s.register_relay("eu", "relay-eu:443", None, true, None); // shared/official
        s.register_relay("us", "relay-a:443", Some(net_a.id.clone()), true, None); // a-only

        let a = s.list_relays(&net_a.id);
        assert_eq!(a.len(), 2); // shared + a-scoped
        let b = s.list_relays(&net_b.id);
        assert_eq!(b.len(), 1); // shared only
        assert_eq!(b[0].region, "eu");
    }

    #[test]
    fn magicdns_resolves_device_name_case_insensitively() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, None, None).unwrap();
        let d = s.enroll(&inv.code, "home-nas", "k", 1000).unwrap();
        assert_eq!(s.resolve(&net.id, "home-nas"), d.address_v4);
        assert_eq!(s.resolve(&net.id, "HOME-NAS"), d.address_v4);
        assert_eq!(s.resolve(&net.id, "nope"), None);
    }

    #[test]
    fn advertise_route_unknown_device_fails() {
        let s = Store::new();
        assert_eq!(
            s.advertise_route("dev-x", "10.0.0.0/8").unwrap_err(),
            StoreError::DeviceNotFound
        );
    }

    #[test]
    fn epoch_subscription_observes_bumps() {
        let s = Store::new();
        let net = s.create_network("n");
        let inv = s.create_invite(&net.id, None, None).unwrap();
        let rx = s.subscribe(&net.id).unwrap();
        assert_eq!(*rx.borrow(), 0);

        s.enroll(&inv.code, "d1", "k1", 1000).unwrap();
        assert_eq!(*rx.borrow(), 1); // enroll bumped + notified
        let d2 = s.enroll(&inv.code, "d2", "k2", 1000).unwrap();
        assert_eq!(*rx.borrow(), 2);
        s.revoke_device(&d2.id).unwrap();
        assert_eq!(*rx.borrow(), 3);
    }
}
