use std::time::Duration;

/// Configuration for AnyTLS transport.
/// All fields are runtime-configurable via config.toml or API.
#[derive(Clone, Debug)]
pub struct AnytlsConfig {
    // ── Authentication ──
    /// AnyTLS auth password, auto-derived from node_id via `derive_password()`.
    /// NOT manually configured — set via `AnytlsConfig::with_node_id()`.
    pub password: String,

    // ── TLS ──
    /// TLS server name (SNI) sent in ClientHello
    pub server_name: String,
    /// Path to TLS certificate file (PEM, server only)
    pub cert_path: Option<String>,
    /// Path to TLS private key file (PEM, server only)
    pub key_path: Option<String>,
    /// Skip TLS certificate verification (for self-signed certs)
    pub insecure_skip_verify: bool,

    // ── Bond pool ──
    /// Number of bonded TLS connections per peer (default: 3, range: 1-8)
    pub bond_connections: usize,
    /// Timeout for secondary connections to join a bond group (default: 10s)
    pub bond_join_timeout: Duration,
    /// Interval between automatic reconnect attempts for dead connections (default: 5s)
    pub bond_reconnect_interval: Duration,

    // ── Health check ──
    /// Interval between health check pings per connection (default: 10s).
    /// Drives ping + replenishment cadence. Lowered from 30s after 2026-05-20
    /// bond disconnect audit: middlebox idle-reset observed at ~14s, so 30s
    /// missed the window entirely. See docs/task/09-vpn-bond-disconnect-audit.md.
    pub health_check_interval: Duration,
    /// Ping timeout before marking a connection as failed (default: 5s)
    pub health_check_timeout: Duration,
    /// Consecutive failures before fully degrading a connection (default: 2)
    pub max_consecutive_failures: u32,

    // ── Thresholds ──
    /// RTT above this (microseconds) triggers weight reduction (default: 5_000_000 = 5s)
    pub degraded_rtt_us: u64,
    /// RTT below this (microseconds) allows weight recovery (default: 2_000_000 = 2s)
    pub recovery_rtt_us: u64,
    /// Loss above this per-mille triggers weight reduction (default: 100 = 10%)
    pub degraded_loss_permille: u32,
    /// Loss below this per-mille allows weight recovery (default: 30 = 3%)
    pub recovery_loss_permille: u32,
}

/// Fixed salt for password derivation — ensures same node_id always produces same password
const DERIVE_SALT: &[u8] = b"fp-anytls-v1";

impl AnytlsConfig {
    /// Derive AnyTLS password from node_id.
    /// Both server and client call this with the same node_id → same password.
    /// Formula: SHA256(salt || node_id), hex-encoded.
    pub fn derive_password(node_id: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(DERIVE_SALT);
        hasher.update(node_id.as_bytes());
        let hash = hasher.finalize();
        hex::encode(hash)
    }

    /// Create config with password auto-derived from node_id.
    /// Sets insecure_skip_verify = true because Flux nodes commonly use self-signed certs;
    /// authentication is done at the Noise protocol layer, not TLS.
    pub fn with_node_id(node_id: &str) -> Self {
        Self {
            password: Self::derive_password(node_id),
            insecure_skip_verify: true,
            ..Default::default()
        }
    }

    /// Clamp bond_connections to [1, 8]
    pub fn effective_bond_connections(&self) -> usize {
        self.bond_connections.clamp(1, 8)
    }
}

impl Default for AnytlsConfig {
    fn default() -> Self {
        Self {
            password: String::new(),
            server_name: "localhost".to_string(),
            cert_path: None,
            key_path: None,
            insecure_skip_verify: false,

            bond_connections: 3,
            bond_join_timeout: Duration::from_secs(10),
            bond_reconnect_interval: Duration::from_secs(5),

            health_check_interval: Duration::from_secs(10),
            health_check_timeout: Duration::from_secs(5),
            max_consecutive_failures: 2,

            degraded_rtt_us: 5_000_000,
            recovery_rtt_us: 2_000_000,
            degraded_loss_permille: 100,
            recovery_loss_permille: 30,
        }
    }
}
