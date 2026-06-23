//! Relay routing hub: the transport-independent core of the relay server.
//!
//! Keeps a `pubkey → outbound-frame sender` registry and routes a client's
//! `SendPacket{dst,payload}` to the destination as `RecvPacket{src,payload}`.
//! The socket/accept layer (TCP now, anytls/443 later) lives in [`crate::server`]
//! and wraps this; the routing logic here is fully testable in-process.
//!
//! Each client's outbound queue is **bounded** (`queue_cap`) so a slow or stalled
//! client cannot make the relay buffer unboundedly: once full, further frames for
//! it are dropped (relayed traffic is best-effort, like UDP — wg re-drives state).

use std::collections::HashMap;

use parking_lot::Mutex;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender, channel};

use crate::proto::{Frame, PublicKey};

/// Default per-client outbound send-queue depth (mirrors iroh-relay ~512).
pub const DEFAULT_QUEUE_CAP: usize = 512;

/// Result of routing a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Routed {
    /// Delivered to the destination's outbound queue.
    Delivered,
    /// Destination connected but its queue was full; frame dropped (best-effort).
    Dropped(PublicKey),
    /// Destination not connected; caller should reply `PeerGone` to the sender.
    PeerGone(PublicKey),
    /// Frame was not a routable client→relay datagram (ignored).
    Ignored,
}

pub struct Hub {
    peers: Mutex<HashMap<PublicKey, Sender<Frame>>>,
    queue_cap: usize,
}

impl Default for Hub {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_QUEUE_CAP)
    }
}

impl Hub {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(queue_cap: usize) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            queue_cap: queue_cap.max(1),
        }
    }

    /// Register a connected client. Returns `(sender, receiver)`: the socket layer
    /// drains `receiver` to write frames back to that client, and keeps `sender`
    /// to deliver self-addressed replies (Pong, PeerGone) into the same stream.
    /// Replaces any prior session for this pubkey.
    pub fn connect(&self, pubkey: PublicKey) -> (Sender<Frame>, Receiver<Frame>) {
        let (tx, rx) = channel(self.queue_cap);
        self.peers.lock().insert(pubkey, tx.clone());
        (tx, rx)
    }

    /// Remove a client, but only if the currently-registered session is still
    /// `tx` (so a reconnect that replaced this session is not clobbered).
    pub fn disconnect_session(&self, pubkey: &PublicKey, tx: &Sender<Frame>) {
        let mut g = self.peers.lock();
        if let Some(cur) = g.get(pubkey)
            && cur.same_channel(tx)
        {
            g.remove(pubkey);
        }
    }

    pub fn disconnect(&self, pubkey: &PublicKey) {
        self.peers.lock().remove(pubkey);
    }

    pub fn connected(&self, pubkey: &PublicKey) -> bool {
        self.peers.lock().contains_key(pubkey)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.lock().len()
    }

    /// Route one inbound frame from `src`. Only `SendPacket` is forwarded
    /// (delivered as `RecvPacket`); everything else is `Ignored` here.
    pub fn route(&self, src: PublicKey, frame: Frame) -> Routed {
        let Frame::SendPacket { dst, payload } = frame else {
            return Routed::Ignored;
        };
        let guard = self.peers.lock();
        match guard.get(&dst) {
            Some(tx) => match tx.try_send(Frame::RecvPacket { src, payload }) {
                Ok(()) => Routed::Delivered,
                Err(TrySendError::Full(_)) => Routed::Dropped(dst),
                Err(TrySendError::Closed(_)) => Routed::PeerGone(dst),
            },
            None => Routed::PeerGone(dst),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn forwards_send_to_dst_as_recv() {
        let hub = Hub::new();
        let a = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        let (_tx_a, _rx_a) = hub.connect(a);
        let (_tx_b, mut rx_b) = hub.connect(b);
        assert_eq!(hub.peer_count(), 2);

        let out = hub.route(
            a,
            Frame::SendPacket {
                dst: b,
                payload: vec![1, 2, 3],
            },
        );
        assert_eq!(out, Routed::Delivered);

        let got = rx_b.recv().await.unwrap();
        assert_eq!(
            got,
            Frame::RecvPacket {
                src: a,
                payload: vec![1, 2, 3]
            }
        );
    }

    #[tokio::test]
    async fn unknown_dst_is_peer_gone() {
        let hub = Hub::new();
        let a = [1u8; 32];
        let missing = [9u8; 32];
        let (_tx_a, _rx_a) = hub.connect(a);
        assert_eq!(
            hub.route(
                a,
                Frame::SendPacket {
                    dst: missing,
                    payload: vec![]
                }
            ),
            Routed::PeerGone(missing)
        );
    }

    #[tokio::test]
    async fn disconnect_then_route_is_peer_gone() {
        let hub = Hub::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let (_tx_a, _rx_a) = hub.connect(a);
        let (_tx_b, _rx_b) = hub.connect(b);
        hub.disconnect(&b);
        assert!(!hub.connected(&b));
        assert_eq!(
            hub.route(
                a,
                Frame::SendPacket {
                    dst: b,
                    payload: vec![0]
                }
            ),
            Routed::PeerGone(b)
        );
    }

    #[tokio::test]
    async fn non_send_frames_are_ignored() {
        let hub = Hub::new();
        let a = [1u8; 32];
        let (_tx, _rx) = hub.connect(a);
        assert_eq!(hub.route(a, Frame::Ping { data: [0; 8] }), Routed::Ignored);
    }

    #[tokio::test]
    async fn full_queue_drops_not_blocks() {
        let hub = Hub::with_capacity(2);
        let a = [1u8; 32];
        let b = [2u8; 32];
        let (_tx_a, _rx_a) = hub.connect(a);
        let (_tx_b, _rx_b) = hub.connect(b); // never drained → fills up
        assert_eq!(
            hub.route(
                a,
                Frame::SendPacket {
                    dst: b,
                    payload: vec![1]
                }
            ),
            Routed::Delivered
        );
        assert_eq!(
            hub.route(
                a,
                Frame::SendPacket {
                    dst: b,
                    payload: vec![2]
                }
            ),
            Routed::Delivered
        );
        // third exceeds cap → dropped, not blocked
        assert_eq!(
            hub.route(
                a,
                Frame::SendPacket {
                    dst: b,
                    payload: vec![3]
                }
            ),
            Routed::Dropped(b)
        );
    }

    #[tokio::test]
    async fn reconnect_then_old_session_disconnect_is_noop() {
        let hub = Hub::new();
        let a = [1u8; 32];
        let (tx_old, _rx_old) = hub.connect(a);
        let (_tx_new, _rx_new) = hub.connect(a); // replaces session
        // old session cleanup must NOT evict the new session
        hub.disconnect_session(&a, &tx_old);
        assert!(hub.connected(&a));
    }
}
