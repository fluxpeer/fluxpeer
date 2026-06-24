//! Node configuration + key generation.

use serde::Deserialize;

use fp_crypto::x25519::{PublicKey, StaticSecret};

#[derive(Deserialize)]
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
    /// This device acts as an EXIT NODE: enable IP forwarding + NAT masquerade so
    /// peers routing 0.0.0.0/0 through it actually egress to the internet. This flag
    /// only sets up the LOCAL forwarding/NAT — for peers to actually route through it,
    /// an admin must additionally advertise + approve the `0.0.0.0/0` route for this
    /// device at the control-server (`POST /devices/:id/routes {"prefix":"0.0.0.0/0"}`
    /// then `POST /routes/:id/approve`, or the equivalent CLI / admin-lite action).
    /// Declaring a node as everyone's exit is privileged, so it is deliberately NOT
    /// self-service: the node cannot advertise the route itself (admin-gated).
    #[serde(default)]
    pub(crate) exit_node: bool,
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
