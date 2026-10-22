// SPDX-License-Identifier: BSD-3-Clause
//! Bounded per-peer replay and outstanding-probe state. A MAC authenticates a
//! message, but only a response to our own probe proves return reachability.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use parking_lot::Mutex;
use crate::util::DISCO_REPLAY_WINDOW_SECS;

type TxId = [u8; 12];
type PeerKey = [u8; 32];
const CAPACITY: usize = 128;
pub(crate) type Routes = Arc<Mutex<HashMap<TxId, (PeerKey, u64)>>>;
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
pub(crate) fn owner(routes: &Routes, id: &TxId) -> Option<PeerKey> {
    routes.lock().get(id).filter(|(_, expiry)| *expiry >= now()).map(|(peer, _)| *peer)
}
fn timestamp(id: &TxId) -> Option<u64> { Some(u64::from_be_bytes(id.get(..8)?.try_into().ok()?)) }

#[derive(Default)]
pub(crate) struct Probes {
    seen: HashMap<TxId, u64>,
    pending: HashMap<TxId, (Vec<SocketAddr>, u64)>,
}
impl Probes {
    /// Keep entries until their MAC timestamp leaves the acceptance window,
    /// including future-skewed timestamps. Never evict still-valid seen entries.
    pub(crate) fn accept_ping(&mut self, id: TxId, now: u64) -> bool {
        self.seen.retain(|_, expires| *expires >= now);
        let Some(sent) = timestamp(&id) else { return false; };
        if now.abs_diff(sent) > DISCO_REPLAY_WINDOW_SECS || self.seen.contains_key(&id) || self.seen.len() >= CAPACITY { return false; }
        self.seen.insert(id, sent.saturating_add(DISCO_REPLAY_WINDOW_SECS)); true
    }
    pub(crate) fn start(&mut self, peer: PeerKey, targets: Vec<SocketAddr>, routes: &Routes, now: u64) -> Option<TxId> {
        self.pending.retain(|_, (_, expires)| *expires >= now);
        if targets.is_empty() || self.pending.len() >= CAPACITY { return None; }
        let mut id = [0; 12];
        let (time, random) = id.split_at_mut(8);
        time.copy_from_slice(&now.to_be_bytes());
        if let Err(error) = getrandom::getrandom(random) { tracing::warn!(%error, "disco nonce generation failed"); return None; }
        let mut routes = routes.lock(); routes.retain(|_, (_, expires)| *expires >= now);
        if routes.contains_key(&id) { return None; }
        let expires = now.saturating_add(DISCO_REPLAY_WINDOW_SECS);
        routes.insert(id, (peer, expires)); self.pending.insert(id, (targets, expires)); Some(id)
    }
    pub(crate) fn pending(&self, id: &TxId, from: SocketAddr, now: u64) -> bool {
        self.pending.get(id).is_some_and(|(targets, expires)| *expires >= now && targets.contains(&from))
    }
    pub(crate) fn finish(&mut self, id: &TxId, from: SocketAddr, routes: &Routes, now: u64) -> bool {
        if !self.pending(id, from, now) { return false; }
        self.pending.remove(id); routes.lock().remove(id); true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(sent: u64, nonce: u32) -> TxId {
        let mut id = [0; 12]; id[..8].copy_from_slice(&sent.to_be_bytes()); id[8..].copy_from_slice(&nonce.to_be_bytes()); id
    }
    #[test]
    fn replay_cache_covers_full_mac_window_without_live_eviction() {
        let mut state = Probes::default();
        assert!(state.accept_ping(id(130, 0), 100));
        assert!(!state.accept_ping(id(130, 0), 159));
        assert!(!state.accept_ping(id(130, 0), 160));
        assert!(!state.accept_ping(id(130, 0), 161)); // MAC expired
        for n in 1..=128 { assert!(state.accept_ping(id(161, n), 161)); }
        assert!(!state.accept_ping(id(161, 129), 161));
        assert!(!state.accept_ping(id(161, 1), 161));
        assert!(state.accept_ping(id(192, 129), 192));
    }
    #[test]
    fn pong_requires_pending_id_expected_source_and_unexpired_probe_once() {
        let mut state = Probes::default(); let routes = Routes::default();
        let addr = "127.0.0.1:10".parse().unwrap(); let wrong = "127.0.0.1:11".parse().unwrap();
        let id = state.start([1; 32], vec![addr], &routes, 100).unwrap();
        assert!(!state.finish(&id, wrong, &routes, 101));
        assert!(state.finish(&id, addr, &routes, 101));
        assert!(!state.finish(&id, addr, &routes, 101)); assert!(routes.lock().is_empty());
        let id = state.start([1; 32], vec![addr], &routes, 100).unwrap();
        assert!(!state.finish(&id, addr, &routes, 131));
    }
}
