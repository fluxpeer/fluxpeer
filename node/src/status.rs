//! Live per-peer status + byte counters, shared between the data-plane workers
//! (writers) and the local status socket (`fluxpeer show` / wg-UAPI, reader).
//!
//! wg has no bandwidth concept — only monotonic rx/tx byte counters + a
//! latest-handshake timestamp; `wg show` is a snapshot and realtime UIs derive
//! rate from polling deltas. We mirror that: per-packet atomic counters here,
//! plus the mesh state wg can't model (transport rung, rtt).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

// Transport rung (the ladder) — what wg can't express.
pub(crate) const T_NONE: u8 = 0;
pub(crate) const T_UDP_DIRECT: u8 = 1;
pub(crate) const T_TCP_DIRECT: u8 = 2;
pub(crate) const T_RELAY: u8 = 3;

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn transport_name(t: u8) -> &'static str {
    match t {
        T_UDP_DIRECT => "udp-direct",
        T_TCP_DIRECT => "tcp-direct",
        T_RELAY => "relay",
        _ => "—",
    }
}

/// One peer's shared live counters + snapshot fields. Per-packet fields are
/// atomics (hot path); the rest are refreshed by the owning worker each 1 Hz tick.
pub(crate) struct PeerStat {
    pub(crate) rx_bytes: AtomicU64,
    pub(crate) tx_bytes: AtomicU64,
    /// Wall-clock unix secs of the last completed handshake (0 = never).
    pub(crate) last_handshake_unix: AtomicU64,
    /// Smoothed RTT in microseconds (0 = unknown).
    pub(crate) rtt_us: AtomicU64,
    pub(crate) transport: AtomicU8,
    pub(crate) endpoint: Mutex<Option<SocketAddr>>,
    /// Allowed-IPs (set at creation; routes can append later — kept simple here).
    pub(crate) allowed_ips: Vec<String>,
}

impl PeerStat {
    pub(crate) fn new(allowed_ips: Vec<String>) -> Arc<Self> {
        Arc::new(Self {
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            last_handshake_unix: AtomicU64::new(0),
            rtt_us: AtomicU64::new(0),
            transport: AtomicU8::new(T_NONE),
            endpoint: Mutex::new(None),
            allowed_ips,
        })
    }
    pub(crate) fn add_rx(&self, n: usize) {
        self.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub(crate) fn add_tx(&self, n: usize) {
        self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub(crate) fn mark_handshake(&self) {
        self.last_handshake_unix.store(now_unix(), Ordering::Relaxed);
    }
}

/// `peer pubkey → its shared stat`. Workers insert on add, remove on revoke.
pub(crate) type StatusRegistry = Arc<RwLock<HashMap<[u8; 32], Arc<PeerStat>>>>;

pub(crate) fn registry() -> StatusRegistry {
    Arc::new(RwLock::new(HashMap::new()))
}

/// A flat, owned snapshot of one peer for serialisation (JSON / wg-UAPI).
pub(crate) struct PeerSnapshot {
    pub(crate) pubkey: [u8; 32],
    pub(crate) endpoint: Option<SocketAddr>,
    pub(crate) transport: u8,
    pub(crate) allowed_ips: Vec<String>,
    pub(crate) last_handshake_unix: u64,
    pub(crate) rtt_us: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
}

/// Snapshot every known peer (point-in-time read of the shared registry).
pub(crate) fn snapshot(reg: &StatusRegistry) -> Vec<PeerSnapshot> {
    reg.read()
        .iter()
        .map(|(pk, s)| PeerSnapshot {
            pubkey: *pk,
            endpoint: *s.endpoint.lock(),
            transport: s.transport.load(Ordering::Relaxed),
            allowed_ips: s.allowed_ips.clone(),
            last_handshake_unix: s.last_handshake_unix.load(Ordering::Relaxed),
            rtt_us: s.rtt_us.load(Ordering::Relaxed),
            rx_bytes: s.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: s.tx_bytes.load(Ordering::Relaxed),
        })
        .collect()
}
