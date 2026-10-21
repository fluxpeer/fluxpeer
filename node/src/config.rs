//! Node configuration + key generation.

use serde::Deserialize;

use fp_crypto::x25519::{PublicKey, StaticSecret};

#[derive(Clone, Deserialize)]
pub(crate) struct Config {
    /// 64-hex (32-byte) x25519 private key (its public key is enrolled at the server).
    pub(crate) private_key: String,
    /// This node's device id at the control-server (from enrollment).
    pub(crate) device_id: String,
    /// Control-server base URL, e.g. `http://192.168.31.136:8090`.
    pub(crate) control_server: String,
    /// Per-device auth token issued at enroll, sent as the bearer on this device's
    /// control-server calls (config pull / endpoint report / route advertise). The
    /// server rejects device calls without it, so it must be present for any device
    /// enrolled after per-device auth landed.
    #[serde(default)]
    pub(crate) auth_token: Option<String>,
    /// UDP port to bind for the tunnel (also the advertised endpoint port).
    pub(crate) listen_port: u16,
    /// TUN interface name (e.g. "fp0").
    pub(crate) tun_name: String,
    /// Overlay prefix length for the TUN's connected route (e.g. 24).
    pub(crate) prefix_len: u8,
    /// Explicit advertised `ip:port` endpoints; if empty, advertise the STUN
    /// reflexive (public) address (if `stun_server` is set) + the local IPv4.
    #[serde(default)]
    pub(crate) advertise: Vec<String>,
    /// UDP STUN server (the relay's STUN addr) to learn our reflexive/public
    /// `ip:port` behind NAT, so peers can hole-punch to us.
    #[serde(default)]
    pub(crate) stun_server: Option<String>,
    /// Optional relay-server address for fallback (e.g. "192.168.31.136:3478").
    #[serde(default)]
    pub(crate) relay: Option<String>,
    /// Connect to the relay over AnyTLS/443 (TLS 1.3 + anti-fingerprint) instead
    /// of plain TCP. `relay_node_id` is the shared AnyTLS password seed.
    #[serde(default)]
    pub(crate) relay_anytls: bool,
    #[serde(default)]
    pub(crate) relay_node_id: Option<String>,
    /// Aggregate N TCP links per relay (health-weighted bond) instead of a single
    /// plain-TCP connection. Mutually exclusive with `relay_anytls`.
    #[serde(default)]
    pub(crate) relay_bond: bool,
    /// Number of links a bonded relay aggregates (tcp-bond OR anytls), clamped to
    /// [1,8]. Unset → the transport default (3).
    #[serde(default)]
    pub(crate) relay_bond_links: Option<usize>,
    /// Force all wg traffic through the relay (skip direct/disco).
    #[serde(default)]
    pub(crate) force_relay: bool,
    /// LOCAL wg settings the device sets for itself (desktop "Settings" edits),
    /// overriding what the control-server distributes. No admin needed.
    #[serde(default)]
    pub(crate) mtu: Option<i32>,
    #[serde(default)]
    pub(crate) dns: Vec<String>,
    /// Local override for acting as an EXIT NODE (IP forwarding + NAT masquerade,
    /// so peers routing 0.0.0.0/0 through us actually egress to the internet).
    ///
    /// Tri-state (AD-1): `true` = force ON (legacy behavior, works even against
    /// an old control-server); absent = follow the control-plane, which is the
    /// single source of truth (NAT runs while this device has an APPROVED
    /// default route — `self_exit` in the pulled config). A legacy JSON
    /// `"exit_node": false` migrates to absent (see `de_exit_node`); an explicit
    /// local refusal is `exit_veto` below. Writers (daemon/CLI) only ever write
    /// `true` or remove the key.
    #[serde(default, deserialize_with = "de_exit_node")]
    pub(crate) exit_node: Option<bool>,
    /// Explicit local VETO against being an exit: even when the control-plane
    /// approved a default route for this device (`self_exit`), do NOT enable
    /// forwarding/NAT. Wins over every other signal.
    #[serde(default)]
    pub(crate) exit_veto: bool,
    /// Explicitly trust external firewall forwarding policy despite preflight uncertainty.
    #[serde(default)]
    pub(crate) firewall_trust_external: bool,
    /// Use an EXIT PEER for this device's own internet traffic (full-tunnel).
    /// `None`/`"off"` = split-tunnel (default): all peers' default prefixes are
    /// stripped. `"auto"` = pick the first exit-capable peer (pubkey order) with
    /// a known endpoint or a configured relay.
    /// `"<pubkey hex>"` = pin that exit peer; unknown/non-exit ⇒ error + split.
    #[serde(default)]
    pub(crate) use_exit: Option<String>,
    /// Subnets to EXCLUDE from the tunnel (split-exclude). Only meaningful when a
    /// peer is an exit node (AllowedIPs 0.0.0.0/0, full-tunnel): these CIDRs get a
    /// more-specific bypass route via the original physical gateway, so they keep
    /// routing normally instead of through fp. The control-server + relay IPs, the
    /// exit endpoint, and the local LAN are excluded automatically.
    #[serde(default)]
    pub(crate) exclude_routes: Vec<String>,
    /// EXTERNAL TUN file descriptor to adopt instead of creating our own device.
    /// Set on mobile (Android `VpnService` / iOS `NEPacketTunnelProvider`), where the
    /// app — not the engine — owns the tun: the OS hands us a ready fd whose address,
    /// routes, MTU and DNS are already configured by the VPN API. When present the
    /// node runs the SAME data plane as everywhere else (disco/relay/multi-peer/exit
    /// as a peer) but skips device creation + host route/DNS install (the platform
    /// owns those), so a phone is a first-class mesh node, not a thin gateway client.
    #[serde(default)]
    pub(crate) tun_fd: Option<i32>,
}

/// Backward-compatible `exit_node` deserialization (AD-1 migration): a legacy
/// `"exit_node": false` meant "not forced on", which under the new tri-state is
/// simply ABSENT (follow the control-plane) — the explicit refusal moved to
/// `exit_veto`. So only `true` survives as `Some(true)`.
fn de_exit_node<'de, D>(d: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<bool>::deserialize(d)?.filter(|b| *b))
}

impl Config {
    /// Whether THIS device runs forwarding/NAT as an exit right now, given the
    /// control-plane's `self_exit` (this device has an approved default route).
    /// Precedence (AD-1): `exit_veto` > `exit_node` (force on/off) > `self_exit`.
    #[cfg(test)]
    pub(crate) fn nat_on(&self, self_exit: bool) -> bool {
        crate::nat_on(self.exit_node, self.exit_veto, self_exit)
    }
}

/// Generate a fresh x25519 keypair, returning `(private_hex, public_hex)`. Shared by
/// `keygen` (prints them) and `join` (enrolls the public key, writes the private).
pub(crate) fn keypair() -> (String, String) {
    // x25519 private key — must come from the OS CSPRNG. getrandom maps to
    // getrandom(2) on Linux, BCryptGenRandom on Windows, getentropy on macOS;
    // NOT /dev/urandom, which doesn't exist on Windows.
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG (getrandom) failed");
    let priv_key = StaticSecret::from(bytes);
    (
        hex::encode(priv_key.to_bytes()),
        hex::encode(PublicKey::from(&priv_key).to_bytes()),
    )
}

pub fn keygen() {
    let (priv_hex, pub_hex) = keypair();
    println!("private_key = {priv_hex}");
    println!("public_key  = {pub_hex}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_json(extra: &str) -> String {
        format!(
            r#"{{
                "private_key": "{sk}", "device_id": "d1",
                "control_server": "http://127.0.0.1:8080",
                "listen_port": 51820, "tun_name": "fp0", "prefix_len": 24
                {extra}
            }}"#,
            sk = "00".repeat(32),
        )
    }

    fn parse(extra: &str) -> Config {
        serde_json::from_str(&cfg_json(extra)).expect("config parses")
    }

    #[test]
    fn external_firewall_trust_requires_explicit_boolean_opt_in() {
        assert!(!parse("").firewall_trust_external);
        assert!(parse(r#", "firewall_trust_external": true"#).firewall_trust_external);
        assert!(!parse(r#", "firewall_trust_external": false"#).firewall_trust_external);
        assert!(serde_json::from_str::<Config>(&cfg_json(r#", "firewall_trust_external": "true""#)).is_err());
    }

    #[test]
    fn legacy_exit_node_false_migrates_to_absent() {
        // Old configs wrote `"exit_node": false`; that now means "follow the
        // control-plane", NOT an explicit veto.
        let c = parse(r#", "exit_node": false"#);
        assert_eq!(c.exit_node, None);
        assert!(!c.exit_veto);
        assert!(c.nat_on(true)); // follows self_exit
        assert!(!c.nat_on(false));
    }

    #[test]
    fn exit_node_true_forces_on_regardless_of_control() {
        let c = parse(r#", "exit_node": true"#);
        assert_eq!(c.exit_node, Some(true));
        assert!(c.nat_on(false)); // forced on even without an approved route
        assert!(c.nat_on(true));
    }

    #[test]
    fn absent_exit_node_follows_control() {
        let c = parse("");
        assert_eq!(c.exit_node, None);
        assert!(c.nat_on(true));
        assert!(!c.nat_on(false));
    }

    #[test]
    fn exit_veto_wins_over_everything() {
        let c = parse(r#", "exit_node": true, "exit_veto": true"#);
        assert!(!c.nat_on(true));
        assert!(!c.nat_on(false));
        let c = parse(r#", "exit_veto": true"#);
        assert!(!c.nat_on(true));
    }

    #[test]
    fn use_exit_defaults_to_split() {
        let c = parse("");
        assert_eq!(c.use_exit, None);
        let c = parse(r#", "use_exit": "auto""#);
        assert_eq!(c.use_exit.as_deref(), Some("auto"));
        let c = parse(r#", "use_exit": "off""#);
        assert_eq!(c.use_exit.as_deref(), Some("off"));
    }
}
