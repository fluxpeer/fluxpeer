//! Connection-policy / path selection.
//!
//! Pure state machine: tracks the liveness of each candidate path to a peer and
//! picks the best per the preference ladder
//! `UDP direct → TCP direct → UDP relay → TCP relay → TCP/443 relay`.
//! Direct is always preferred over relay; failed paths are never selected; the
//! relay backstop is kept so a connection can start on relay and upgrade.

/// Candidate path kinds, in preference order (lowest = most preferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathKind {
    UdpDirect = 0,
    TcpDirect = 1,
    UdpRelay = 2,
    TcpRelay = 3,
    /// TCP over 443 (anytls) — last-resort, censorship-resistant.
    Tcp443Relay = 4,
}

impl PathKind {
    /// The ladder, most- to least-preferred.
    pub const LADDER: [PathKind; 5] = [
        PathKind::UdpDirect,
        PathKind::TcpDirect,
        PathKind::UdpRelay,
        PathKind::TcpRelay,
        PathKind::Tcp443Relay,
    ];

    /// Whether this path is a direct (non-relay) path.
    pub fn is_direct(self) -> bool {
        matches!(self, PathKind::UdpDirect | PathKind::TcpDirect)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    Untested,
    Alive,
    Failed,
}

/// The set of paths to a single peer and their liveness.
#[derive(Debug, Clone)]
pub struct PathSet {
    states: [PathState; 5],
}

impl Default for PathSet {
    fn default() -> Self {
        Self {
            states: [PathState::Untested; 5],
        }
    }
}

impl PathSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self, kind: PathKind) -> PathState {
        self.states[kind as usize]
    }

    pub fn mark_alive(&mut self, kind: PathKind) {
        self.states[kind as usize] = PathState::Alive;
    }

    pub fn mark_failed(&mut self, kind: PathKind) {
        self.states[kind as usize] = PathState::Failed;
    }

    /// Best currently-usable path: the most-preferred `Alive` path on the ladder.
    pub fn best(&self) -> Option<PathKind> {
        PathKind::LADDER
            .into_iter()
            .find(|&k| self.state(k) == PathState::Alive)
    }

    /// True if we currently have a direct path selected (so relay can be idled).
    pub fn has_direct(&self) -> bool {
        self.best().map(PathKind::is_direct).unwrap_or(false)
    }

    /// Whether to keep probing for something better than the current best
    /// (i.e. the best is a relay but some direct path is still untested).
    pub fn should_keep_probing(&self) -> bool {
        match self.best() {
            None => true,
            Some(b) if !b.is_direct() => {
                // a relay is in use — keep trying still-untested direct paths
                [PathKind::UdpDirect, PathKind::TcpDirect]
                    .into_iter()
                    .any(|d| self.state(d) == PathState::Untested)
            }
            Some(_) => false, // already direct
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn prefers_udp_direct_when_alive() {
        let mut p = PathSet::new();
        p.mark_alive(PathKind::UdpDirect);
        p.mark_alive(PathKind::TcpRelay);
        assert_eq!(p.best(), Some(PathKind::UdpDirect));
        assert!(p.has_direct());
        assert!(!p.should_keep_probing());
    }

    #[test]
    fn falls_back_to_relay_when_direct_failed() {
        let mut p = PathSet::new();
        p.mark_failed(PathKind::UdpDirect);
        p.mark_failed(PathKind::TcpDirect);
        p.mark_alive(PathKind::UdpRelay);
        assert_eq!(p.best(), Some(PathKind::UdpRelay));
        assert!(!p.has_direct());
        // both direct paths failed → no point probing
        assert!(!p.should_keep_probing());
    }

    #[test]
    fn relay_in_use_keeps_probing_untested_direct() {
        let mut p = PathSet::new();
        p.mark_alive(PathKind::Tcp443Relay); // started on last-resort relay
        // direct still untested → should keep trying to punch
        assert!(p.should_keep_probing());
    }

    #[test]
    fn promotes_direct_over_relay_once_punched() {
        let mut p = PathSet::new();
        p.mark_alive(PathKind::UdpRelay);
        assert_eq!(p.best(), Some(PathKind::UdpRelay));
        // hole punch succeeds:
        p.mark_alive(PathKind::UdpDirect);
        assert_eq!(p.best(), Some(PathKind::UdpDirect));
        assert!(p.has_direct());
    }

    #[test]
    fn none_when_nothing_alive() {
        let mut p = PathSet::new();
        assert_eq!(p.best(), None);
        assert!(p.should_keep_probing());
        p.mark_failed(PathKind::UdpDirect);
        assert_eq!(p.best(), None);
    }

    #[test]
    fn ladder_is_ordered() {
        assert!(PathKind::UdpDirect < PathKind::TcpDirect);
        assert!(PathKind::TcpDirect < PathKind::UdpRelay);
        assert!(PathKind::TcpRelay < PathKind::Tcp443Relay);
    }
}
