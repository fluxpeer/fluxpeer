use std::time::Duration;

/// Configuration for TCP bond transport (no TLS).
/// Controls bond pool size, health check intervals, and degradation thresholds.
#[derive(Clone, Debug)]
pub struct TcpBondConfig {
    // -- Bond pool --
    /// Number of bonded TCP connections per peer (default: 3, range: 1-8)
    pub bond_connections: usize,
    /// Timeout for secondary connections to join a bond group (default: 10s)
    pub bond_join_timeout: Duration,
    /// Interval between automatic reconnect attempts for dead connections (default: 5s)
    pub bond_reconnect_interval: Duration,

    // -- Health check --
    /// Interval between health check pings per connection (default: 30s)
    pub health_check_interval: Duration,
    /// Ping timeout before marking a connection as failed (default: 5s)
    pub health_check_timeout: Duration,
    /// Consecutive failures before fully degrading a connection (default: 3)
    pub max_consecutive_failures: u32,

    // -- Thresholds --
    /// RTT above this (microseconds) triggers weight reduction (default: 5_000_000 = 5s)
    pub degraded_rtt_us: u64,
    /// RTT below this (microseconds) allows weight recovery (default: 2_000_000 = 2s)
    pub recovery_rtt_us: u64,
    /// Loss above this per-mille triggers weight reduction (default: 100 = 10%)
    pub degraded_loss_permille: u32,
    /// Loss below this per-mille allows weight recovery (default: 30 = 3%)
    pub recovery_loss_permille: u32,
}

impl TcpBondConfig {
    /// Clamp bond_connections to [1, 8]
    pub fn effective_bond_connections(&self) -> usize {
        self.bond_connections.clamp(1, 8)
    }
}

impl Default for TcpBondConfig {
    fn default() -> Self {
        Self {
            bond_connections: 3,
            bond_join_timeout: Duration::from_secs(10),
            bond_reconnect_interval: Duration::from_secs(5),

            health_check_interval: Duration::from_secs(30),
            health_check_timeout: Duration::from_secs(5),
            max_consecutive_failures: 3,

            degraded_rtt_us: 5_000_000,
            recovery_rtt_us: 2_000_000,
            degraded_loss_permille: 100,
            recovery_loss_permille: 30,
        }
    }
}

#[allow(clippy::disallowed_types)]
static TCP_BOND_CONFIG: std::sync::RwLock<Option<TcpBondConfig>> = std::sync::RwLock::new(None);

/// Set the TCP bond config. Can be called multiple times (e.g., when switching servers).
pub fn set_tcp_bond_config(config: TcpBondConfig) {
    if let Ok(mut guard) = TCP_BOND_CONFIG.write() {
        *guard = Some(config);
    }
}

pub(crate) fn get_config_cloned() -> TcpBondConfig {
    TCP_BOND_CONFIG
        .read()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default()
}
