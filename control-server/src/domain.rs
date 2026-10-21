//! Coordination-plane core entities.
//!
//! In-memory data shapes; PostgreSQL persistence via SeaORM lands
//! next. Mirrors the on-wire protocol shapes (no billing — that is
//! closed `cloud/`).

use serde::{Deserialize, Serialize};

/// A private network (a "tailnet"-equivalent). Owns its overlay address pools
/// and a monotonic config epoch used for hot config push.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub id: String,
    pub name: String,
    /// IPv4 overlay pool (default derived from CGNAT 100.64.0.0/10).
    pub ipv4_pool: String,
    /// IPv6 ULA prefix, auto-generated /48.
    pub ipv6_ula: String,
    /// Monotonic epoch; bumps on any config change, drives client sync.
    pub config_epoch: u64,
}

/// Device status (peer-level revocation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceStatus {
    Active,
    Revoked,
}

/// A device/peer enrolled in a network. Identity = Curve25519 public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub network_id: String,
    pub name: String,
    /// Curve25519 public key (base64); private key never leaves the device.
    pub wg_public_key: String,
    /// Centrally-allocated stable overlay addresses.
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
    pub status: DeviceStatus,
}

/// An enrollment invite: expiry, use-count limit, network scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub code: String,
    pub network_id: String,
    /// Unix seconds; `None` = no expiry.
    pub expires_at: Option<i64>,
    /// `None` = unlimited.
    pub max_uses: Option<u32>,
    pub uses: u32,
}

/// A registered relay node. `network_id = None`
/// means a shared/official relay available to all networks; `Some` scopes it to
/// one self-hosted network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayNode {
    pub id: String,
    pub region: String,
    /// Reachable relay endpoint (e.g. `relay.example.org:443`).
    pub url: String,
    pub network_id: Option<String>,
    /// Connect over AnyTLS/443 (TLS 1.3 + anti-fingerprint) instead of plain TCP.
    #[serde(default)]
    pub anytls: bool,
    /// UDP STUN address clients query for their reflexive (public) endpoint — the
    /// relay doubles as STUN. Defaults to `url`'s host on the
    /// relay port when omitted at registration.
    #[serde(default)]
    pub stun_url: Option<String>,
}

/// A subnet route advertised by a device acting as a Subnet Router:
/// other peers reach `prefix` via this device's overlay address. Off until
/// approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub network_id: String,
    pub device_id: String,
    /// CIDR of the real LAN behind the router, e.g. `192.168.1.0/24`.
    pub prefix: String,
    pub approved: bool,
}

/// A peer entry in a device's pushed/pulled config (≈ wg `[Peer]`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub wg_public_key: String,
    /// Overlay addresses the peer owns (`<v4>/32`, `<v6>/128`); subnet routes
    /// append here. An approved default route (`0.0.0.0/0`) is STILL listed here
    /// for backward compatibility with old nodes; new nodes strip it unless the
    /// user opted into an exit (`use_exit`) — see `exit`.
    pub allowed_ips: Vec<String>,
    /// The peer's reachable candidate `ip:port` endpoints, for disco hole-punching
    /// Empty until the peer reports them; the local node probes these for a
    /// direct path, else falls back to relay.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// This peer is an approved EXIT (it has an approved default route
    /// `0.0.0.0/0` / `::/0`). The control-plane is the single source of truth
    /// for exit-ness; absent (old control) ⇒ the node infers it from a default
    /// prefix in `allowed_ips`.
    #[serde(default)]
    pub exit: bool,
}

/// What a device fetches to configure itself + its peers (config-pull).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub network_id: String,
    pub config_epoch: u64,
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
    pub peers: Vec<PeerConfig>,
    /// Relay directory usable by this device (network-scoped + shared/official),
    /// so nodes pull relay/STUN endpoints from coordination instead of pinning
    /// them in local node config.
    #[serde(default)]
    pub relays: Vec<RelayNode>,
    /// Admin-set TUN MTU (wg-editable setting); `None` = node default.
    #[serde(default)]
    pub mtu: Option<i32>,
    /// Admin-set DNS servers the node installs (wg-quick `DNS =`); empty = none.
    #[serde(default)]
    pub dns: Vec<String>,
    /// THIS device is an approved EXIT (it has an approved default route): the
    /// node dynamically enables local forwarding/NAT while this holds (unless
    /// locally forced on via `exit_node: true` or vetoed via `exit_veto: true`).
    #[serde(default)]
    pub self_exit: bool,
}

/// Whether `prefix` is a default route (`0.0.0.0/0` or `::/0`) — the marker of
/// an approved EXIT device (AD-1: the control-plane is the source of truth).
pub fn is_default_prefix(prefix: &str) -> bool {
    prefix.parse::<fluxpeer_sdk::prefix::IpPrefix>().is_ok_and(|p| p.length() == 0)
}

/// Advertised routes must be CIDRs; normalize their network and prefix length.
pub fn normalize_prefix(value: &str) -> Option<String> {
    if !value.contains('/') { return None; }
    value.parse::<fluxpeer_sdk::prefix::IpPrefix>().ok().map(|p| p.to_string())
}

impl Invite {
    /// Whether the invite can still be redeemed at `now` (unix seconds),
    /// ignoring clock skew. Pure logic — unit-tested below.
    pub fn is_redeemable(&self, now: i64) -> bool {
        let not_expired = self.expires_at.map(|e| now < e).unwrap_or(true);
        let has_uses = self.max_uses.map(|m| self.uses < m).unwrap_or(true);
        not_expired && has_uses
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn invite(expires_at: Option<i64>, max_uses: Option<u32>, uses: u32) -> Invite {
        Invite {
            code: "c".into(),
            network_id: "n".into(),
            expires_at,
            max_uses,
            uses,
        }
    }

    #[test]
    fn unlimited_invite_is_redeemable() {
        assert!(invite(None, None, 99).is_redeemable(1_000));
    }

    #[test]
    fn expired_invite_is_not_redeemable() {
        assert!(!invite(Some(500), None, 0).is_redeemable(1_000));
        assert!(invite(Some(2_000), None, 0).is_redeemable(1_000));
    }

    #[test]
    fn used_up_invite_is_not_redeemable() {
        assert!(!invite(None, Some(3), 3).is_redeemable(1_000));
        assert!(invite(None, Some(3), 2).is_redeemable(1_000));
    }
}

/// One device entry in a batch import (`fp import`): parsed from a wg.conf
/// `[Interface]`/`[Peer]`, carrying a fixed overlay address preserved verbatim
/// rather than auto-allocated. Private keys never reach the server — only the
/// (already-public) `wg_public_key`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportDevice {
    pub name: String,
    pub wg_public_key: String,
    #[serde(default)]
    pub address_v4: Option<String>,
    #[serde(default)]
    pub address_v6: Option<String>,
    /// Pinned `ip:port` endpoint(s) from the peer's `Endpoint =` line.
    #[serde(default)]
    pub endpoints: Vec<String>,
}

/// Outcome of a batch import: devices newly created, plus the public keys that
/// were skipped because they were already enrolled (idempotent re-import).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportResult {
    pub created: Vec<Device>,
    pub skipped: Vec<String>,
}

/// An admin audit-log entry (who did what, when).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: i64,
    pub actor: String,
    pub action: String,
}
