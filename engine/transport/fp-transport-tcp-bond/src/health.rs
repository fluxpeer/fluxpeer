use crate::config::TcpBondConfig;
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
/// Thresholds are injected from TcpBondConfig at construction time.
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
    pub fn new(config: &TcpBondConfig) -> Self {
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
