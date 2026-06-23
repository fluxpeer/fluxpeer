//! NAT classification + connection diagnostics.
//! The STUN socket probing itself needs the network
//! (host); the **classification and recommendation algorithms here are pure and
//! unit-tested**, so the decision logic is verified independently of I/O.

use std::collections::HashSet;
use std::net::SocketAddr;

/// NAT behaviour inferred from STUN observations across multiple servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClass {
    /// Observed public address equals local — no NAT (directly reachable).
    Open,
    /// Same public mapping from all servers — cone NAT; hole punching works.
    EndpointIndependent,
    /// Different public ports per server — symmetric NAT; punching unreliable.
    Symmetric,
    /// No STUN response at all — UDP likely blocked.
    Blocked,
    /// Too few responses to classify (need ≥2 servers).
    Unknown,
}

impl NatClass {
    /// Whether direct hole punching is plausible for this NAT class.
    pub fn punchable(self) -> bool {
        matches!(self, NatClass::Open | NatClass::EndpointIndependent)
    }
}

/// Classify NAT from our local socket address and the public addresses observed
/// by each STUN server (`None` = that server didn't respond).
pub fn classify_nat(local: SocketAddr, observations: &[Option<SocketAddr>]) -> NatClass {
    let seen: Vec<SocketAddr> = observations.iter().flatten().copied().collect();
    if seen.is_empty() {
        return NatClass::Blocked;
    }
    if seen.contains(&local) {
        return NatClass::Open;
    }
    let distinct: HashSet<SocketAddr> = seen.iter().copied().collect();
    if distinct.len() > 1 {
        NatClass::Symmetric
    } else if seen.len() >= 2 {
        NatClass::EndpointIndependent
    } else {
        NatClass::Unknown
    }
}

/// Raw connectivity probe inputs (gathered by the host networking layer).
#[derive(Debug, Clone)]
pub struct Probe {
    pub udp_ok: bool,
    pub tcp_ok: bool,
    pub relay_ok: bool,
    pub nat: NatClass,
    pub first_connect_ms: Option<u32>,
    pub last_error: Option<String>,
}

/// Recommended connection strategy (maps to the fp-path ladder).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnStrategy {
    DirectUdp,
    DirectTcp,
    Relay,
    /// Nothing works — cannot connect.
    None,
}

/// A human + machine readable diagnosis.
#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub strategy: ConnStrategy,
    pub can_connect: bool,
    pub summary: String,
}

/// Recommend a strategy from a probe (the "one-click diagnose" core).
pub fn diagnose(p: &Probe) -> Diagnosis {
    let direct_ok = p.nat.punchable();
    let strategy = if p.udp_ok && direct_ok {
        ConnStrategy::DirectUdp
    } else if p.tcp_ok && direct_ok {
        ConnStrategy::DirectTcp
    } else if p.relay_ok {
        ConnStrategy::Relay
    } else {
        ConnStrategy::None
    };
    let can_connect = strategy != ConnStrategy::None;
    let summary = match strategy {
        ConnStrategy::DirectUdp => "direct UDP connection available".to_string(),
        ConnStrategy::DirectTcp => "direct TCP connection available".to_string(),
        ConnStrategy::Relay => match p.nat {
            NatClass::Symmetric => "symmetric NAT — using relay".to_string(),
            NatClass::Blocked => "UDP blocked — using relay".to_string(),
            _ => "direct unavailable — using relay".to_string(),
        },
        ConnStrategy::None => {
            format!(
                "cannot connect{}",
                p.last_error.as_ref().map(|e| format!(": {e}")).unwrap_or_default()
            )
        }
    };
    Diagnosis {
        strategy,
        can_connect,
        summary,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classify_blocked_when_no_responses() {
        assert_eq!(classify_nat(a("10.0.0.2:1234"), &[None, None]), NatClass::Blocked);
    }

    #[test]
    fn classify_open_when_observed_equals_local() {
        assert_eq!(
            classify_nat(a("1.2.3.4:5000"), &[Some(a("1.2.3.4:5000"))]),
            NatClass::Open
        );
    }

    #[test]
    fn classify_cone_when_all_same() {
        let obs = [Some(a("9.9.9.9:40000")), Some(a("9.9.9.9:40000"))];
        assert_eq!(classify_nat(a("10.0.0.2:1234"), &obs), NatClass::EndpointIndependent);
        assert!(classify_nat(a("10.0.0.2:1234"), &obs).punchable());
    }

    #[test]
    fn classify_symmetric_when_ports_differ() {
        let obs = [Some(a("9.9.9.9:40000")), Some(a("9.9.9.9:40001"))];
        assert_eq!(classify_nat(a("10.0.0.2:1234"), &obs), NatClass::Symmetric);
        assert!(!classify_nat(a("10.0.0.2:1234"), &obs).punchable());
    }

    #[test]
    fn classify_unknown_with_single_response() {
        assert_eq!(
            classify_nat(a("10.0.0.2:1234"), &[Some(a("9.9.9.9:40000")), None]),
            NatClass::Unknown
        );
    }

    #[test]
    fn diagnose_prefers_direct_udp_on_cone() {
        let p = Probe {
            udp_ok: true,
            tcp_ok: true,
            relay_ok: true,
            nat: NatClass::EndpointIndependent,
            first_connect_ms: Some(40),
            last_error: None,
        };
        assert_eq!(diagnose(&p).strategy, ConnStrategy::DirectUdp);
    }

    #[test]
    fn diagnose_falls_back_to_relay_on_symmetric() {
        let p = Probe {
            udp_ok: true,
            tcp_ok: true,
            relay_ok: true,
            nat: NatClass::Symmetric,
            first_connect_ms: None,
            last_error: None,
        };
        let d = diagnose(&p);
        assert_eq!(d.strategy, ConnStrategy::Relay);
        assert!(d.can_connect);
        assert!(d.summary.contains("symmetric"));
    }

    #[test]
    fn diagnose_none_when_nothing_works() {
        let p = Probe {
            udp_ok: false,
            tcp_ok: false,
            relay_ok: false,
            nat: NatClass::Blocked,
            first_connect_ms: None,
            last_error: Some("timeout".into()),
        };
        let d = diagnose(&p);
        assert_eq!(d.strategy, ConnStrategy::None);
        assert!(!d.can_connect);
        assert!(d.summary.contains("timeout"));
    }
}
