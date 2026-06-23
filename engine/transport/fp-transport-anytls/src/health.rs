use crate::config::AnytlsConfig;
use portable_atomic::AtomicU64;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Summary of bond-group health across all connections.
pub struct BondHealthSummary {
    pub alive_count: usize,
    pub dead_count: usize,
    pub avg_rtt_ms: u64,
    pub total_bytes: u64,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Per-connection health metrics with atomic updates.
/// Thresholds are injected from AnytlsConfig at construction time.
pub struct ConnHealth {
    rtt_us: AtomicU64,
    loss_permille: AtomicU32,
    active_streams: AtomicU32,
    total_bytes: AtomicU64,
    weight: AtomicU32,
    consecutive_failures: AtomicU32,
    last_ping: Mutex<Instant>,
    ping_sent_at: Mutex<Option<Instant>>,
    last_activity: AtomicU64,
    // thresholds (copied from config, immutable after construction)
    max_failures: u32,
    degraded_rtt_us: u64,
    recovery_rtt_us: u64,
    degraded_loss_permille: u32,
    recovery_loss_permille: u32,
}

const EWMA_OLD: u64 = 7;
const EWMA_NEW: u64 = 3;
const EWMA_DIV: u64 = 10;

impl ConnHealth {
    pub fn new(config: &AnytlsConfig) -> Self {
        Self {
            rtt_us: AtomicU64::new(0),
            loss_permille: AtomicU32::new(0),
            active_streams: AtomicU32::new(0),
            total_bytes: AtomicU64::new(0),
            weight: AtomicU32::new(100),
            consecutive_failures: AtomicU32::new(0),
            last_ping: Mutex::new(Instant::now()),
            ping_sent_at: Mutex::new(None),
            last_activity: AtomicU64::new(unix_now_secs()),
            max_failures: config.max_consecutive_failures,
            degraded_rtt_us: config.degraded_rtt_us,
            recovery_rtt_us: config.recovery_rtt_us,
            degraded_loss_permille: config.degraded_loss_permille,
            recovery_loss_permille: config.recovery_loss_permille,
        }
    }

    /// Lower score = better connection.
    pub fn score(&self) -> u64 {
        if self.weight.load(Ordering::Relaxed) == 0 {
            return u64::MAX;
        }
        let rtt_ms = self.rtt_us.load(Ordering::Relaxed) / 1000;
        let loss = self.loss_permille.load(Ordering::Relaxed) as u64;
        let streams = self.active_streams.load(Ordering::Relaxed) as u64;
        rtt_ms
            .saturating_mul(2)
            .saturating_add(loss.saturating_mul(10))
            .saturating_add(streams.saturating_mul(5))
    }

    pub fn record_rtt(&self, rtt_us: u64) {
        let old = self.rtt_us.load(Ordering::Relaxed);
        let v = if old == 0 {
            rtt_us
        } else {
            (old * EWMA_OLD + rtt_us * EWMA_NEW) / EWMA_DIV
        };
        self.rtt_us.store(v, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if v < self.recovery_rtt_us && self.loss_permille.load(Ordering::Relaxed) < self.recovery_loss_permille {
            let w = self.weight.load(Ordering::Relaxed);
            if w < 100 {
                self.weight.store((w + 10).min(100), Ordering::Relaxed);
            }
        }
        if v > self.degraded_rtt_us {
            let w = self.weight.load(Ordering::Relaxed);
            self.weight.store(w.saturating_sub(20), Ordering::Relaxed);
        }
    }

    pub fn record_failure(&self) {
        let f = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if f >= self.max_failures {
            self.weight.store(0, Ordering::Relaxed);
            tracing::warn!(failures = f, "Connection degraded");
        }
    }

    pub fn record_loss(&self, lost: u32, total: u32) {
        if total == 0 {
            return;
        }
        let sample = (lost as u64 * 1000 / total as u64) as u32;
        let old = self.loss_permille.load(Ordering::Relaxed) as u64;
        let v = if old == 0 {
            sample as u64
        } else {
            (old * EWMA_OLD + sample as u64 * EWMA_NEW) / EWMA_DIV
        };
        self.loss_permille.store(v as u32, Ordering::Relaxed);
        if v as u32 > self.degraded_loss_permille {
            let w = self.weight.load(Ordering::Relaxed);
            self.weight.store(w.saturating_sub(20), Ordering::Relaxed);
        }
    }

    pub async fn mark_ping_sent(&self) {
        *self.ping_sent_at.lock().await = Some(Instant::now());
    }

    pub async fn process_pong(&self) {
        if let Some(t) = self.ping_sent_at.lock().await.take() {
            let rtt = t.elapsed().as_micros() as u64;
            self.record_rtt(rtt);
            *self.last_ping.lock().await = Instant::now();
        }
    }

    pub fn increment_streams(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
    }
    pub fn decrement_streams(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
    pub fn add_bytes(&self, n: u64) {
        self.total_bytes.fetch_add(n, Ordering::Relaxed);
    }
    pub fn weight(&self) -> u32 {
        self.weight.load(Ordering::Relaxed)
    }
    pub fn is_dead(&self) -> bool {
        self.weight.load(Ordering::Relaxed) == 0
    }
    pub fn rtt_ms(&self) -> u64 {
        self.rtt_us.load(Ordering::Relaxed) / 1000
    }
    pub fn active_streams(&self) -> u32 {
        self.active_streams.load(Ordering::Relaxed)
    }
    pub fn reset_weight(&self) {
        self.weight.store(100, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    /// Update last activity timestamp to current time.
    pub fn touch_activity(&self) {
        self.last_activity.store(unix_now_secs(), Ordering::Relaxed);
    }

    /// Unix timestamp (seconds) of last activity.
    pub fn last_activity_secs(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// Returns true if the connection has had no activity for `timeout_secs`
    /// AND is already fully degraded (weight == 0).
    pub fn is_stale(&self, timeout_secs: u64) -> bool {
        let now = unix_now_secs();
        let last = self.last_activity.load(Ordering::Relaxed);
        now.saturating_sub(last) > timeout_secs && self.weight.load(Ordering::Relaxed) == 0
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> AnytlsConfig {
        AnytlsConfig::default()
    }

    // ── ConnHealth basic functionality ──

    #[test]
    fn test_new_initial_values() {
        let h = ConnHealth::new(&default_config());
        assert_eq!(h.weight(), 100);
        assert_eq!(h.rtt_ms(), 0);
        assert!(!h.is_dead());
        assert_eq!(h.active_streams(), 0);
        assert_eq!(h.total_bytes(), 0);
        // last_activity should be close to now
        let now = unix_now_secs();
        assert!(now.saturating_sub(h.last_activity_secs()) <= 1);
    }

    #[test]
    fn test_record_rtt_first_sample() {
        let h = ConnHealth::new(&default_config());
        // First sample: no EWMA, use raw value
        h.record_rtt(10_000); // 10ms in us
        assert_eq!(h.rtt_ms(), 10); // 10_000 us / 1000 = 10 ms
    }

    #[test]
    fn test_record_rtt_ewma() {
        let h = ConnHealth::new(&default_config());
        h.record_rtt(10_000); // first: 10_000
        h.record_rtt(20_000); // EWMA: (10000*7 + 20000*3)/10 = 13_000
        assert_eq!(h.rtt_us.load(Ordering::Relaxed), 13_000);
    }

    #[test]
    fn test_record_rtt_low_recovers_weight() {
        let cfg = AnytlsConfig {
            recovery_rtt_us: 100_000, // 100ms
            recovery_loss_permille: 50,
            ..Default::default()
        };
        let h = ConnHealth::new(&cfg);
        // Artificially reduce weight
        h.weight.store(70, Ordering::Relaxed);
        // Record low RTT (below recovery threshold) → weight should increase
        h.record_rtt(50_000); // 50ms < 100ms recovery threshold
        assert_eq!(h.weight(), 80); // 70 + 10 = 80
    }

    #[test]
    fn test_record_rtt_high_degrades_weight() {
        let cfg = AnytlsConfig {
            degraded_rtt_us: 100_000, // 100ms
            ..Default::default()
        };
        let h = ConnHealth::new(&cfg);
        assert_eq!(h.weight(), 100);
        // Record high RTT (above degraded threshold)
        h.record_rtt(200_000); // 200ms > 100ms
        assert_eq!(h.weight(), 80); // 100 - 20 = 80
    }

    #[test]
    fn test_record_rtt_clears_failures() {
        let h = ConnHealth::new(&default_config());
        h.record_failure();
        h.record_failure();
        assert_eq!(h.consecutive_failures.load(Ordering::Relaxed), 2);
        h.record_rtt(1000);
        assert_eq!(h.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_failure_degrades_after_max() {
        let cfg = AnytlsConfig {
            max_consecutive_failures: 3,
            ..Default::default()
        };
        let h = ConnHealth::new(&cfg);
        assert!(!h.is_dead());
        h.record_failure(); // 1
        assert!(!h.is_dead());
        h.record_failure(); // 2
        assert!(!h.is_dead());
        h.record_failure(); // 3 → dead
        assert!(h.is_dead());
        assert_eq!(h.weight(), 0);
    }

    #[test]
    fn test_record_loss_ewma() {
        let h = ConnHealth::new(&default_config());
        // First sample: 100/1000 = 100 permille
        h.record_loss(100, 1000);
        assert_eq!(h.loss_permille.load(Ordering::Relaxed), 100);
        // Second: EWMA (100*7 + 200*3)/10 = 130
        h.record_loss(200, 1000);
        assert_eq!(h.loss_permille.load(Ordering::Relaxed), 130);
    }

    #[test]
    fn test_record_loss_zero_total_noop() {
        let h = ConnHealth::new(&default_config());
        h.record_loss(10, 0);
        assert_eq!(h.loss_permille.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_record_loss_high_degrades_weight() {
        let cfg = AnytlsConfig {
            degraded_loss_permille: 50, // 5%
            ..Default::default()
        };
        let h = ConnHealth::new(&cfg);
        // 100/1000 = 100 permille > 50 → degrade
        h.record_loss(100, 1000);
        assert_eq!(h.weight(), 80); // 100 - 20
    }

    #[test]
    fn test_touch_activity_and_last_activity() {
        let h = ConnHealth::new(&default_config());
        let before = unix_now_secs();
        h.touch_activity();
        let after = unix_now_secs();
        let last = h.last_activity_secs();
        assert!(last >= before && last <= after);
    }

    #[test]
    fn test_is_stale_dead_and_inactive() {
        let h = ConnHealth::new(&default_config());
        // weight=0 (dead) + inactive >90s → stale
        h.weight.store(0, Ordering::Relaxed);
        // Set last_activity to 100s ago
        let old = unix_now_secs().saturating_sub(100);
        h.last_activity.store(old, Ordering::Relaxed);
        assert!(h.is_stale(90));
    }

    #[test]
    fn test_is_stale_alive_not_stale() {
        let h = ConnHealth::new(&default_config());
        // weight > 0 → not stale even if inactive
        let old = unix_now_secs().saturating_sub(100);
        h.last_activity.store(old, Ordering::Relaxed);
        assert!(!h.is_stale(90)); // weight=100, not dead
    }

    #[test]
    fn test_is_stale_dead_but_recent_activity() {
        let h = ConnHealth::new(&default_config());
        h.weight.store(0, Ordering::Relaxed);
        h.touch_activity(); // just now
        assert!(!h.is_stale(90)); // dead but recently active
    }

    #[test]
    fn test_score_dead_returns_max() {
        let h = ConnHealth::new(&default_config());
        h.weight.store(0, Ordering::Relaxed);
        assert_eq!(h.score(), u64::MAX);
    }

    #[test]
    fn test_score_formula() {
        let h = ConnHealth::new(&default_config());
        // rtt=10ms (10_000 us), loss=50 permille, streams=2
        h.rtt_us.store(10_000, Ordering::Relaxed);
        h.loss_permille.store(50, Ordering::Relaxed);
        h.active_streams.store(2, Ordering::Relaxed);
        // score = rtt_ms*2 + loss*10 + streams*5 = 10*2 + 50*10 + 2*5 = 20+500+10 = 530
        assert_eq!(h.score(), 530);
    }

    #[test]
    fn test_reset_weight() {
        let h = ConnHealth::new(&default_config());
        h.weight.store(0, Ordering::Relaxed);
        h.consecutive_failures.store(5, Ordering::Relaxed);
        h.reset_weight();
        assert_eq!(h.weight(), 100);
        assert_eq!(h.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_streams_and_bytes() {
        let h = ConnHealth::new(&default_config());
        h.increment_streams();
        h.increment_streams();
        assert_eq!(h.active_streams(), 2);
        h.decrement_streams();
        assert_eq!(h.active_streams(), 1);
        h.add_bytes(1024);
        h.add_bytes(2048);
        assert_eq!(h.total_bytes(), 3072);
    }

    #[tokio::test]
    async fn test_ping_pong_records_rtt() {
        let h = ConnHealth::new(&default_config());
        h.mark_ping_sent().await;
        // Small delay to get non-zero RTT
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        h.process_pong().await;
        // RTT should be > 0 after pong
        assert!(h.rtt_us.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_weight_recovery_capped_at_100() {
        let cfg = AnytlsConfig {
            recovery_rtt_us: 1_000_000,
            recovery_loss_permille: 500,
            ..Default::default()
        };
        let h = ConnHealth::new(&cfg);
        h.weight.store(95, Ordering::Relaxed);
        h.record_rtt(100); // low RTT → recover +10, but cap at 100
        assert_eq!(h.weight(), 100);
    }

    #[test]
    fn test_weight_degradation_floors_at_zero() {
        let cfg = AnytlsConfig {
            degraded_rtt_us: 100,
            ..Default::default()
        };
        let h = ConnHealth::new(&cfg);
        h.weight.store(10, Ordering::Relaxed);
        h.record_rtt(200); // high RTT → degrade -20, but floor at 0
        assert_eq!(h.weight(), 0);
    }
}
