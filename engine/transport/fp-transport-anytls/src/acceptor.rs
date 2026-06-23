//! `AnytlsAcceptor`: the reusable "process one already-established TcpStream"
//! unit for AnyTLS.
//!
//! It owns the TLS acceptor, password hash, bond-group join-window registry,
//! and the ready channel. `feed_stream()` accepts an externally-supplied
//! `TcpStream` (from a per-port listener OR from a demux listener) and spawns a
//! per-connection task to drive TLS→auth→bond→yamux and read the first Noise
//! packet OFF the accept hot path. `accept_ready()` pops connections whose
//! first packet has already arrived.
//!
//! The head-of-line (HOL) blocking fix is preserved verbatim here: a connection
//! that never sends its first packet only burns its own per-connection task and
//! its bond resources until the join timeout — it can never block other
//! handshakes or the accept loop.

use crate::bond::{BondGroup, BondedReceiver, BondedSender};
use crate::config::AnytlsConfig;
use crate::conn::accept_server_connection;
use crate::health::ConnHealth;
use fp_transport::AcceptResponse;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A bond group whose first Noise packet has already been received off the
/// accept() hot path: `(group, peer_ip, first_packet)`.
type ReadyMsg = (Arc<BondGroup>, std::net::IpAddr, Vec<u8>);

struct PendingBond {
    group: Arc<BondGroup>,
    arrived: std::sync::atomic::AtomicU8,
}

/// Reusable processor for already-established AnyTLS TcpStreams.
///
/// Construct once (with TLS acceptor + password + config), then `feed_stream()`
/// any number of accepted `TcpStream`s into it and pop ready connections via
/// `accept_ready()`.
pub struct AnytlsAcceptor {
    tls_acceptor: Arc<tokio_rustls::TlsAcceptor>,
    password_hash: [u8; 32],
    config: AnytlsConfig,
    /// Bond-group join-window registry, keyed by bond_id.
    pending: Arc<RwLock<HashMap<[u8; 16], PendingBond>>>,
    /// A per-connection task reads the first Noise packet (with timeout) OFF the
    /// accept() hot path, then delivers a fully-ready
    /// (BondGroup, peer_ip, first_packet) tuple here. `accept_ready()` only pops
    /// ready connections, so a connection that never sends its first packet can
    /// never wedge the listener (no head-of-line blocking).
    primary_tx: tokio::sync::mpsc::Sender<ReadyMsg>,
    primary_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<ReadyMsg>>,
}

impl AnytlsAcceptor {
    pub fn new(tls_acceptor: Arc<tokio_rustls::TlsAcceptor>, password_hash: [u8; 32], config: AnytlsConfig) -> Self {
        let (primary_tx, primary_rx) = tokio::sync::mpsc::channel::<ReadyMsg>(256);
        Self {
            tls_acceptor,
            password_hash,
            config,
            pending: Arc::new(RwLock::new(HashMap::new())),
            primary_tx,
            primary_rx: tokio::sync::Mutex::new(primary_rx),
        }
    }

    /// Hand an already-established TcpStream to the acceptor. Spawns a
    /// per-connection task that drives TLS+auth+bond+yamux and reads the first
    /// packet off the hot path. Never blocks the caller (no HOL blocking).
    pub fn feed_stream(self: &Arc<Self>, tcp: tokio::net::TcpStream, peer_addr: SocketAddr) {
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = this.handle_connection(tcp, peer_addr).await {
                tracing::warn!(%peer_addr, "Connection handling failed: {}", e);
            }
        });
    }

    /// Await the next fully-ready bond (first Noise packet already read) and
    /// turn it into an `AcceptResponse`. Cancellation-safe: dropping the future
    /// (e.g. losing a `tokio::select!` race) does not lose a buffered message.
    pub async fn accept_ready(&self) -> Result<AcceptResponse, fp_transport::Error> {
        let (group, peer_ip, first_packet) = {
            let mut rx = self.primary_rx.lock().await;
            rx.recv().await.ok_or(fp_transport::Error::ListenerHasBeenClosed)?
        };

        tracing::info!(%peer_ip, len = first_packet.len(), "AnyTLS listener: ready connection dequeued");
        let sender: Box<dyn fp_transport::TransportSender> = Box::new(BondedSender { group: group.clone() });
        let receiver: Box<dyn fp_transport::TransportReceiver> = Box::new(BondedReceiver { group });
        Ok(AcceptResponse {
            packet: first_packet,
            sender,
            receiver,
            peer_addr: peer_ip,
        })
    }

    async fn handle_connection(
        &self,
        tcp: tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(), fp_transport::Error> {
        let mut accepted = accept_server_connection(tcp, &self.tls_acceptor, &self.password_hash).await?;
        let bond_id = accepted.bond_id;
        let bond_total = accepted.bond_total;
        tracing::info!(%peer_addr, bond_total, "AnyTLS connection accepted");

        // Determine primary vs secondary without holding the lock across awaits.
        // Primary = first connection with this bond_id; secondary = subsequent.
        // `promoted` is `Some(flag)` only for the primary, which owns the
        // first-packet wait task and must flip the flag on success.
        let (is_primary, group, idx, promoted) = {
            let mut pending_w = self.pending.write().await;
            if let Some(pb) = pending_w.get(&bond_id) {
                let group = pb.group.clone();
                let idx = pb.arrived.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                (false, group, idx, None)
            } else {
                let group = BondGroup::new(bond_id);
                // `promoted` is shared only between this connection's cleanup task and
                // its first-packet task (clones below); it intentionally lives outside
                // the `pending` map entry, which is just the join-window registry.
                let promoted = Arc::new(std::sync::atomic::AtomicBool::new(false));
                pending_w.insert(
                    bond_id,
                    PendingBond {
                        group: group.clone(),
                        arrived: std::sync::atomic::AtomicU8::new(0),
                    },
                );
                (true, group, 0u8, Some(promoted))
            }
        }; // lock released before any await

        let conn_idx = if is_primary { 0usize } else { idx as usize + 1 };
        let health = Arc::new(ConnHealth::new(&self.config));
        let group_for_driver = group.clone();
        tokio::spawn(async move {
            let mut first_stream = true;
            while let Some(result) = accepted.next_inbound().await {
                match result {
                    Ok(stream) if first_stream => {
                        first_stream = false;
                        tracing::info!(%peer_addr, is_primary, conn_idx, "yamux inbound stream received");
                        group_for_driver.add_stream(conn_idx, health.clone(), stream).await;
                    }
                    Ok(_stream) => {
                        // Only the first stream belongs to the bonded data path.
                        // Later streams are health-check / control streams; drop them
                        // while still continuing to drive the yamux connection.
                        tracing::debug!(%peer_addr, conn_idx, "dropping extra yamux stream");
                    }
                    Err(e) => {
                        tracing::warn!(%peer_addr, conn_idx, "yamux driver ended: {}", e);
                        break;
                    }
                }
            }
        });

        if !is_primary {
            tracing::info!(
                arrived = idx + 2,
                expected = bond_total,
                "Secondary bond connection joined"
            );
            return Ok(());
        }

        // Primary path. `promoted` is always `Some` here (set in the primary branch
        // above), but handle `None` without panicking to honour the zero-panic rule.
        let Some(promoted) = promoted else {
            tracing::warn!(%peer_addr, "primary path reached without promotion flag, dropping bond");
            group.close();
            return Ok(());
        };

        // Evict the bond from the `pending` join-window map after the join timeout.
        // If the bond was never promoted to a live transport (no first packet read),
        // also `close()` it so it cannot linger as a zombie with `closed=false`.
        // A promoted bond is a live transport owned by the listener/sender/receiver
        // — we must NOT close it here (that would kill a healthy connection at the
        // join-timeout mark, regressing the original remove-only behaviour).
        let pending_cleanup = self.pending.clone();
        let join_timeout = self.config.bond_join_timeout;
        let promoted_for_cleanup = promoted.clone();
        tokio::spawn(async move {
            tokio::time::sleep(join_timeout).await;
            if let Some(evicted) = pending_cleanup.write().await.remove(&bond_id)
                && !promoted_for_cleanup.load(std::sync::atomic::Ordering::SeqCst)
            {
                // Half-formed bond that never received a first packet → reap it.
                // `close()` is idempotent, so racing the first-packet task's own
                // close() is harmless.
                evicted.group.close();
            }
        });

        // Read the FIRST Noise packet off the accept() hot path, in a dedicated
        // per-connection task with a bounded timeout. A connection that never sends
        // its first packet only burns its own task + the bond's resources until the
        // timeout fires — it can never block other handshakes (no HOL blocking).
        //
        // `group.recv()` pulls from ALL bonded connections of this bond_id, not just
        // the primary. tokio mpsc `recv()` is cancellation-safe, so the timeout
        // branch dropping the future cannot lose an already-buffered packet; on
        // timeout we close the group entirely, so any buffered bytes are discarded
        // together with the abandoned half-formed bond — the connection never
        // reached the listener, so there is no upper-layer inconsistency.
        let handshake_timeout = self.config.bond_join_timeout;
        let tx_for_ready = self.primary_tx.clone();
        let peer_ip = peer_addr.ip();
        tokio::spawn(async move {
            match tokio::time::timeout(handshake_timeout, group.recv()).await {
                Ok(Ok(first_packet)) => {
                    // Mark promoted BEFORE handing the live group to the listener,
                    // so the cleanup task can never mistake it for a half-formed bond.
                    promoted.store(true, std::sync::atomic::Ordering::SeqCst);
                    tracing::info!(%peer_ip, len = first_packet.len(), "AnyTLS: first packet received, enqueueing ready bond");
                    if tx_for_ready.send((group, peer_ip, first_packet)).await.is_err() {
                        tracing::warn!(%peer_ip, "Ready channel closed, dropping bond group");
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(%peer_ip, "Bond recv failed before first packet: {}", e);
                    group.close();
                }
                Err(_) => {
                    tracing::warn!(
                        %peer_ip,
                        timeout_secs = handshake_timeout.as_secs(),
                        "First-packet timeout, closing half-formed bond"
                    );
                    group.close();
                }
            }
        });

        tracing::info!(%peer_addr, "Primary bond connection ready, awaiting first packet");
        Ok(())
    }
}
