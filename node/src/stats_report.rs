// SPDX-License-Identifier: BSD-3-Clause
//! Best-effort traffic reporting with change detection and bounded backoff.
use std::time::Duration;
use fluxpeer_sdk::Client;
use serde_json::{Value, json};
use crate::status::{self, StatusRegistry};

fn configured_interval(value: Option<&str>) -> Duration {
    let seconds = match value {
        None => 15,
        Some(value) => match value.parse::<u64>() {
            Ok(seconds @ 1..=3600) => seconds.max(5),
            _ => {
                tracing::warn!("invalid FLUXPEER_STATS_INTERVAL_SECS; using 15 seconds (valid range: 1..=3600, minimum cadence: 5)");
                15
            }
        },
    };
    Duration::from_secs(seconds)
}

#[derive(Debug, PartialEq)]
struct Sample { rx: i64, tx: i64, peers: Value }

fn sample(registry: &StatusRegistry) -> Sample {
    let mut peers = status::snapshot(registry);
    // Registry iteration order must not generate otherwise identical reports.
    peers.sort_unstable_by_key(|peer| peer.pubkey);
    let rx = peers.iter().fold(0_u64, |total, peer| total.saturating_add(peer.rx_bytes));
    let tx = peers.iter().fold(0_u64, |total, peer| total.saturating_add(peer.tx_bytes));
    Sample {
        rx: i64::try_from(rx).unwrap_or(i64::MAX), tx: i64::try_from(tx).unwrap_or(i64::MAX),
        peers: Value::Array(peers.iter().map(|peer| json!({
            "public_key": hex::encode(peer.pubkey), "rx_bytes": peer.rx_bytes, "tx_bytes": peer.tx_bytes,
            "transport": status::transport_name(peer.transport), "last_handshake_unix": peer.last_handshake_unix,
        })).collect()),
    }
}

struct Reporter {
    interval: Duration,
    delay: Duration,
    last_sent: Option<Sample>,
}

impl Reporter {
    fn new(interval: Duration) -> Self { Self { interval, delay: interval, last_sent: None } }

    async fn send(&mut self, client: &Client, device_id: &str, current: Sample) {
        if self.last_sent.as_ref() == Some(&current) {
            self.delay = self.interval;
            return;
        }
        match client.report_stats(device_id, current.rx, current.tx, &current.peers).await {
            Ok(()) => { self.last_sent = Some(current); self.delay = self.interval; }
            Err(error) => {
                // Stats never terminate the node or membership reconciler. Keep
                // the last acknowledged sample so a failed update is retried.
                self.delay = self.delay.saturating_mul(2).min(self.interval.saturating_mul(8));
                let status = error.downcast_ref::<reqwest::Error>().and_then(|error| error.status()).map(|status| status.as_u16());
                tracing::warn!(?status, delay_secs = self.delay.as_secs(), "noncritical stats report failed; backing off");
            }
        }
    }
}

pub(crate) async fn run(registry: StatusRegistry, client: Client, device_id: String) {
    let interval = configured_interval(std::env::var("FLUXPEER_STATS_INTERVAL_SECS").ok().as_deref());
    let mut reporter = Reporter::new(interval);
    loop {
        // Sleep after completion: missed ticks or a slow request cannot cause a burst.
        tokio::time::sleep(reporter.delay).await;
        reporter.send(&client, &device_id, sample(&registry)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use axum::{Router, http::StatusCode, routing::post};

    #[test]
    fn cadence_defaults_clamps_and_rejects_invalid_configuration() {
        assert_eq!(configured_interval(None).as_secs(), 15);
        assert_eq!(configured_interval(Some("1")).as_secs(), 5);
        assert_eq!(configured_interval(Some("5")).as_secs(), 5);
        assert_eq!(configured_interval(Some("60")).as_secs(), 60);
        for invalid in ["0", "-1", "", "3601", "18446744073709551615"] {
            assert_eq!(configured_interval(Some(invalid)).as_secs(), 15);
        }
    }

    #[tokio::test]
    async fn failures_back_off_without_losing_changes_and_success_resets_cadence() {
        let calls = Arc::new(AtomicUsize::new(0)); let count = calls.clone();
        let app = Router::new().route("/api/v1/devices/test/stats", post(move || {
            let count = count.clone();
            async move {
                if count.fetch_add(1, Ordering::SeqCst) < 4 { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::NO_CONTENT }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Client::new(format!("http://{}", listener.local_addr().unwrap()));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let registry = status::registry();
        let mut reporter = Reporter::new(Duration::from_secs(15));
        for delay in [30, 60, 120, 120, 15] {
            reporter.send(&client, "test", sample(&registry)).await;
            assert_eq!(reporter.delay.as_secs(), delay);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        reporter.send(&client, "test", sample(&registry)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 5, "unchanged acknowledged sample must be skipped");
        let peer = status::PeerStat::new(Vec::new());
        registry.write().insert([9;32], peer.clone());
        reporter.send(&client, "test", sample(&registry)).await;
        peer.add_rx(10);
        reporter.send(&client, "test", sample(&registry)).await;
        reporter.send(&client, "test", sample(&registry)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 7, "membership and counter changes each send once");
        server.abort(); let _ = server.await;
    }

    #[test]
    fn samples_are_order_independent_and_preserve_per_peer_changes() {
        let a = status::registry(); let b = status::registry();
        let first = status::PeerStat::new(Vec::new()); let second = status::PeerStat::new(Vec::new());
        first.add_rx(10); second.add_rx(20);
        a.write().insert([1;32], first.clone()); a.write().insert([2;32], second.clone());
        b.write().insert([2;32], second.clone()); b.write().insert([1;32], first.clone());
        assert_eq!(sample(&a), sample(&b));
        let before = sample(&a);
        first.rx_bytes.store(20, Ordering::Relaxed); second.rx_bytes.store(10, Ordering::Relaxed);
        assert_eq!(before.rx, sample(&a).rx);
        assert_ne!(before, sample(&a), "per-peer deltas matter even with equal totals");
    }
}
