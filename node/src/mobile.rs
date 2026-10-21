// SPDX-License-Identifier: BSD-3-Clause
//! Applied engine configuration exported to platform-owned VPN interfaces.

use std::sync::Arc;
use std::time::Duration;
use fluxpeer_sdk::prefix::IpPrefix;
use serde_json::{Value, json};
use crate::control::PeerInfo;

pub type RoutesFn = Arc<dyn Fn(&str) -> std::io::Result<()> + Send + Sync>;

#[derive(Default)]
pub(crate) struct Reporter {
    pub(crate) config: Value,
    pub(crate) callback: Option<RoutesFn>,
    last: Option<String>,
}

impl Reporter {
    pub(crate) fn new(config: Value, callback: Option<RoutesFn>) -> Self {
        Self { config, callback, last: None }
    }

    /// Called only after membership and host effects have both succeeded.
    pub(crate) fn applied(&mut self, peers: &[PeerInfo]) -> std::io::Result<()> {
        if let Some(callback) = &self.callback {
            let json = routes(&self.config, peers).to_string();
            if self.last.as_ref() != Some(&json) {
                callback(&json)?;
                self.last = Some(json);
            }
        }
        Ok(())
    }
}

fn prefixes(value: &Value) -> Vec<IpPrefix> {
    value.as_array().into_iter().flatten().filter_map(|v| v.as_str()?.parse().ok())
        .filter(|p: &IpPrefix| p.length() != 0).collect()
}

fn routes(config: &Value, peers: &[PeerInfo]) -> Value {
    let mut overlay = prefixes(&config["overlay_cidrs"]);
    // Older control servers do not expose their pools. Do not guess a shared
    // CGNAT range: retain their explicit routes until the server is upgraded.
    if overlay.is_empty() {
        for field in ["address_v4", "address_v6"] {
            if let Some(p) = config[field].as_str().and_then(|s| s.parse().ok()) { overlay.push(p); }
        }
    }
    overlay.sort(); overlay.dedup();
    let mut subnets: Vec<IpPrefix> = peers.iter().flat_map(|p| &p.allowed_ips)
        .filter_map(|s| s.parse::<IpPrefix>().ok())
        .filter(|p| p.length() != 0 && !overlay.iter().any(|o| o.length() <= p.length() && o.contains(p.network())))
        .collect();
    subnets.sort(); subnets.dedup();
    json!({
        "address_v4": config["address_v4"], "address_v6": config["address_v6"],
        "overlay_cidrs": overlay.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "subnets": subnets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "selected_exit": crate::selected_exit(peers).map(hex::encode),
        "dns": config["dns"], "mtu": config["mtu"],
    })
}

/// Bootstrap stays alive across missing connectivity; dropping this future stops
/// both an in-flight asynchronous request and its backoff immediately.
pub(crate) async fn retry_control<T, F, Fut>(retry: bool, mut request: F) -> std::io::Result<T>
where F: FnMut() -> Fut, Fut: std::future::Future<Output = std::io::Result<T>> {
    let mut backoff = Backoff::default();
    loop {
        match request().await {
            Ok(value) => return Ok(value),
            Err(error) if retry && !crate::control::terminal_control_error(&error) => {
                tracing::warn!(%error, "mobile control unavailable; retrying without stopping VPN");
                backoff.wait().await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Cancellable, bounded exponential delay for mobile bootstrap and forced relay.
#[derive(Default)]
pub(crate) struct Backoff { attempt: u32 }
impl Backoff {
    pub(crate) async fn wait(&mut self) {
        let delay = Duration::from_secs(1_u64 << self.attempt.min(4));
        self.attempt = self.attempt.saturating_add(1);
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer(id: u8, prefixes: &[&str]) -> PeerInfo {
        PeerInfo { pubkey: [id; 32], candidates: vec![], allowed_ips: prefixes.iter().map(|s| s.to_string()).collect(), overlay: None, exit: true }
    }
    #[test]
    fn stable_overlay_ignores_peer_churn_but_tracks_subnets_and_actual_exit() {
        let cfg = json!({"address_v4":"100.72.1.1","overlay_cidrs":["100.72.1.0/24"],"dns":["192.0.2.53"],"mtu":1420});
        let first = vec![peer(1, &["100.72.1.2/32", "192.168.1.0/24"])];
        let mut more = first.clone(); more.push(peer(2, &["100.72.1.3/32"]));
        assert_eq!(routes(&cfg, &first), routes(&cfg, &more));
        assert!(routes(&cfg, &more)["selected_exit"].is_null());
        more[0].allowed_ips.push("0.0.0.0/0".into());
        let full = routes(&cfg, &more);
        assert_eq!(full["selected_exit"], hex::encode([1; 32]));
        assert_eq!(full["subnets"], json!(["192.168.1.0/24"]));
        more[0].allowed_ips.clear();
        assert_eq!(routes(&cfg, &more)["subnets"], json!([]));
    }
    #[test]
    fn requesting_auto_without_reachable_exit_reports_split() {
        let peers = vec![peer(1, &["0.0.0.0/0"])];
        let (_, filtered) = crate::control::apply_use_exit(&peers, Some("auto"), false);
        assert!(routes(&json!({}), &filtered)["selected_exit"].is_null());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn invalid_embedded_config_closes_injected_fd() {
        use std::os::fd::IntoRawFd;
        use std::io::Read;
        let (owned, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        assert!(crate::run_embedded("invalid", owned.into_raw_fd(), None).await.is_err());
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }

    #[tokio::test]
    async fn absent_network_recovers_without_ending_bootstrap() {
        let mut attempts = 0;
        let recovered = retry_control(true, || {
            attempts += 1;
            std::future::ready(if attempts == 1 { Err(std::io::Error::other("network unavailable")) } else { Ok(42) })
        }).await.unwrap();
        assert_eq!(recovered, 42);
        assert_eq!(attempts, 2);
        let pending = retry_control(true, std::future::pending::<std::io::Result<()>>);
        assert!(tokio::time::timeout(Duration::from_millis(20), pending).await.is_err());
    }

    #[tokio::test]
    async fn bootstrap_backoff_can_be_cancelled_immediately() {
        let mut delay = Backoff::default();
        let result = tokio::time::timeout(Duration::from_millis(20), delay.wait()).await;
        assert!(result.is_err());
    }
}
