//! Per-client inbound rate limiting (token bucket)
//! ("per-client rate limit"). Bounds how many `SendPacket` frames one connection
//! may inject per second so a single client cannot flood the relay.
//!
//! Pure logic — time is passed in, so it is deterministic and unit-tested. The
//! server calls [`TokenBucket::allow`] with `Instant::now()` per inbound frame.

use std::time::Instant;

/// A classic token bucket: `capacity` tokens, refilled at `rate` tokens/sec.
pub struct TokenBucket {
    capacity: f64,
    rate_per_sec: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// `rate_per_sec` sustained frames/sec; `capacity` burst allowance.
    pub fn new(rate_per_sec: u32, capacity: u32, now: Instant) -> Self {
        Self {
            capacity: capacity.max(1) as f64,
            rate_per_sec: rate_per_sec.max(1) as f64,
            tokens: capacity.max(1) as f64,
            last: now,
        }
    }

    /// Try to consume one token at time `now`. Returns `true` if allowed.
    pub fn allow(&mut self, now: Instant) -> bool {
        // Refill based on elapsed time (saturating; clocks are monotonic but be safe).
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
            self.last = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Duration;

    #[test]
    fn allows_up_to_capacity_then_blocks() {
        let t0 = Instant::now();
        let mut tb = TokenBucket::new(10, 3, t0);
        assert!(tb.allow(t0)); // 3 → 2
        assert!(tb.allow(t0)); // 2 → 1
        assert!(tb.allow(t0)); // 1 → 0
        assert!(!tb.allow(t0)); // empty → blocked
    }

    #[test]
    fn refills_over_time() {
        let t0 = Instant::now();
        let mut tb = TokenBucket::new(10, 2, t0);
        assert!(tb.allow(t0));
        assert!(tb.allow(t0));
        assert!(!tb.allow(t0));
        // 200ms at 10/s = 2 tokens refilled
        let t1 = t0 + Duration::from_millis(200);
        assert!(tb.allow(t1));
        assert!(tb.allow(t1));
        assert!(!tb.allow(t1));
    }

    #[test]
    fn refill_caps_at_capacity() {
        let t0 = Instant::now();
        let mut tb = TokenBucket::new(100, 5, t0);
        for _ in 0..5 {
            assert!(tb.allow(t0));
        }
        // long idle would overflow, but cap holds: only `capacity` allowed at once
        let t1 = t0 + Duration::from_secs(10);
        for _ in 0..5 {
            assert!(tb.allow(t1));
        }
        assert!(!tb.allow(t1));
    }
}
