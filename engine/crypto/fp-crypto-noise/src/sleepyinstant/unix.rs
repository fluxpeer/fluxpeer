use std::time::Duration;

use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_gettime};

#[cfg(any(target_os = "macos", target_os = "ios"))]
const CLOCK_ID: ClockId = ClockId::CLOCK_MONOTONIC;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
const CLOCK_ID: ClockId = ClockId::CLOCK_BOOTTIME;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant {
    t: Option<TimeSpec>,
    fallback: std::time::Instant,
}

impl Instant {
    pub(crate) fn now() -> Self {
        // Keep both readings so a failed OS clock never mixes clock domains.
        let fallback = std::time::Instant::now();
        let t = clock_gettime(CLOCK_ID).map_err(|error| tracing::error!(%error, "clock_gettime failed; using monotonic fallback")).ok();
        Self { t, fallback }
    }

    fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        let (Some(current), Some(previous)) = (self.t, earlier.t) else {
            return self.fallback.checked_duration_since(earlier.fallback);
        };
        const NANOSECOND: nix::libc::c_long = 1_000_000_000;
        let (tv_sec, tv_nsec) = if current.tv_nsec() < previous.tv_nsec() {
            (
                current.tv_sec() - previous.tv_sec() - 1,
                current.tv_nsec() - previous.tv_nsec() + NANOSECOND,
            )
        } else {
            (
                current.tv_sec() - previous.tv_sec(),
                current.tv_nsec() - previous.tv_nsec(),
            )
        };

        if tv_sec < 0 {
            None
        } else {
            Some(Duration::new(tv_sec as _, tv_nsec as _))
        }
    }

    pub(crate) fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_failure_uses_one_consistent_fallback_domain() {
        let earlier = Instant::now();
        let later = Instant { t: None, fallback: earlier.fallback + Duration::from_millis(5) };
        assert_eq!(later.duration_since(earlier), Duration::from_millis(5));
        assert_eq!(earlier.duration_since(later), Duration::ZERO);
    }
}
