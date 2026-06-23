//! Implements fp-transport Connector/Listener/TransportSender/TransportReceiver traits.

use crate::bond::{BondGroup, BondedReceiver, BondedSender};
use crate::config::{TcpBondConfig, get_config_cloned};
use crate::conn::accept_server_connection;
use crate::health::ConnHealth;
use fp_transport::{AcceptResponse, Config, Listener, SenderAndReceiver};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct TcpBondConnector;

#[async_trait::async_trait]
impl fp_transport::Connector for TcpBondConnector {
    async fn bind(config: Config) -> Result<Box<dyn Listener>, fp_transport::Error> {
        let tcp_bond_cfg = get_config_cloned();
        let addr = SocketAddr::new(config.endpoint, config.port);

        let tcp_listener = Arc::new(
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(fp_transport::Error::IO)?,
        );

        tracing::info!(%addr, "TCP bond listener bound");

        // Shared state for bond group coordination
        let pending: Arc<RwLock<HashMap<[u8; 16], PendingBond>>> = Arc::new(RwLock::new(HashMap::new()));
        // Channel: primary handler sends (BondGroup, peer_ip). Listener reads first packet.
        type PrimaryMsg = (Arc<BondGroup>, std::net::IpAddr);
        let (primary_tx, primary_rx) = tokio::sync::mpsc::channel::<PrimaryMsg>(256);

        // Shutdown notifier: dropped Listener triggers shutdown of accept_loop.
        let shutdown = Arc::new(tokio::sync::Notify::new());

        // Spawn ONE acceptor task that handles ALL incoming connections concurrently
        let listener_clone = tcp_listener.clone();
        let pending_clone = pending.clone();
        let cfg = tcp_bond_cfg.clone();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            accept_loop(listener_clone, pending_clone, primary_tx, cfg, shutdown_clone).await;
        });

        Ok(Box::new(TcpBondListener {
            primary_rx: tokio::sync::Mutex::new(primary_rx),
            shutdown,
        }))
    }

    async fn connect(config: Config) -> Result<SenderAndReceiver, fp_transport::Error> {
        let tcp_bond_cfg = get_config_cloned();
        let addr = SocketAddr::new(config.endpoint, config.port);

        let group = crate::bond::build_client_bond(&tcp_bond_cfg, addr).await?;

        let n = group.alive_count().await;
        tracing::info!(bond_connections = n, "TCP bond client connected");

        let sender: Box<dyn fp_transport::TransportSender> = Box::new(BondedSender { group: group.clone() });
        let receiver: Box<dyn fp_transport::TransportReceiver> = Box::new(BondedReceiver { group });

        Ok((sender, receiver))
    }
}

// -- Shared state --

struct PendingBond {
    group: Arc<BondGroup>,
    expected: u8,
    arrived: std::sync::atomic::AtomicU8,
}

// -- Listener that receives completed primary bonds from the acceptor task --

type PrimaryMsg = (Arc<BondGroup>, std::net::IpAddr);

struct TcpBondListener {
    primary_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<PrimaryMsg>>,
    shutdown: Arc<tokio::sync::Notify>,
}

impl Drop for TcpBondListener {
    fn drop(&mut self) {
        // Signal the accept_loop task to stop accepting new TCP connections.
        self.shutdown.notify_waiters();
    }
}

#[async_trait::async_trait]
impl Listener for TcpBondListener {
    async fn accept(
        &self,
        closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    ) -> Result<AcceptResponse, fp_transport::Error> {
        loop {
            let (group, peer_ip) = {
                let mut rx = self.primary_rx.lock().await;
                tokio::select! {
                    _ = closer.recv() => {
                        tracing::info!("tcp-bond listener closed, exiting accept loop");
                        // Signal accept_loop too, so the underlying TCP listener stops.
                        self.shutdown.notify_waiters();
                        return Err(fp_transport::Error::ListenerHasBeenClosed);
                    }
                    result = rx.recv() => {
                        result.ok_or(fp_transport::Error::ListenerHasBeenClosed)?
                    }
                }
            };

            // Read first packet (Noise handshake) -- no timeout, dispatcher controls lifetime
            match group.recv().await {
                Ok(first_packet) => {
                    let sender: Box<dyn fp_transport::TransportSender> =
                        Box::new(BondedSender { group: group.clone() });
                    let receiver: Box<dyn fp_transport::TransportReceiver> = Box::new(BondedReceiver { group });
                    return Ok(AcceptResponse {
                        packet: first_packet,
                        sender,
                        receiver,
                        peer_addr: peer_ip,
                    });
                }
                Err(e) => {
                    tracing::warn!("Bond recv failed before first packet: {}", e);
                    continue; // Try next primary
                }
            }
        }
    }
}

// -- Accept loop: runs in a dedicated task, spawns per-connection handlers --

async fn accept_loop(
    tcp_listener: Arc<tokio::net::TcpListener>,
    pending: Arc<RwLock<HashMap<[u8; 16], PendingBond>>>,
    primary_tx: tokio::sync::mpsc::Sender<PrimaryMsg>,
    config: TcpBondConfig,
    shutdown: Arc<tokio::sync::Notify>,
) {
    // Exponential backoff state for accept() errors (FD exhaustion etc.)
    let mut backoff_ms: u64 = 100;
    let mut error_streak: u32 = 0;
    loop {
        let accept_result = tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("tcp-bond accept_loop: shutdown signal received, exiting");
                break;
            }
            r = tcp_listener.accept() => r,
        };

        let (tcp, peer_addr) = match accept_result {
            Ok(r) => {
                // Reset backoff on success
                backoff_ms = 100;
                error_streak = 0;
                r
            }
            Err(e) => {
                error_streak = error_streak.saturating_add(1);
                if error_streak.is_multiple_of(16) {
                    tracing::error!(error_streak, ?e, "tcp-bond accept: persistent failure");
                } else {
                    tracing::warn!(?e, backoff_ms, "tcp-bond accept error, backing off");
                }
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(1000);
                continue;
            }
        };

        // Handle each connection concurrently -- never block the accept loop
        let pend = pending.clone();
        let tx = primary_tx.clone();
        let cfg = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp, peer_addr, &pend, &tx, &cfg).await {
                tracing::warn!(%peer_addr, "Connection handling failed: {}", e);
            }
        });
    }
}

async fn handle_connection(
    tcp: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    pending: &Arc<RwLock<HashMap<[u8; 16], PendingBond>>>,
    primary_tx: &tokio::sync::mpsc::Sender<PrimaryMsg>,
    config: &TcpBondConfig,
) -> Result<(), fp_transport::Error> {
    let mut accepted = accept_server_connection(tcp).await?;
    let bond_id = accepted.bond_id;
    let bond_total = accepted.bond_total;

    // Atomically determine if we're primary (first to insert) or secondary
    let (is_primary, group) = {
        let mut pending_w = pending.write().await;
        if let Some(pb) = pending_w.get(&bond_id) {
            // Secondary: join existing bond
            let group = pb.group.clone();
            if let Some(Ok(stream)) = accepted.next_inbound().await {
                let health = Arc::new(ConnHealth::new(config));
                let idx = pb.arrived.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                group.add_stream(idx as usize + 1, health, stream).await;
                tracing::info!(
                    arrived = idx + 2,
                    expected = pb.expected,
                    "Secondary bond connection joined"
                );
            }
            tokio::spawn(async move { while let Some(Ok(_)) = accepted.next_inbound().await {} });
            return Ok(());
        } else {
            // Primary: create and register
            let group = BondGroup::new(bond_id);
            pending_w.insert(
                bond_id,
                PendingBond {
                    group: group.clone(),
                    expected: bond_total,
                    arrived: std::sync::atomic::AtomicU8::new(0),
                },
            );
            (true, group)
        }
    };

    // Suppress unused variable warning -- is_primary is used implicitly by control flow
    let _ = is_primary;

    // Cleanup timeout
    let pending_cleanup = pending.clone();
    let join_timeout = config.bond_join_timeout;
    tokio::spawn(async move {
        tokio::time::sleep(join_timeout).await;
        pending_cleanup.write().await.remove(&bond_id);
    });

    // Get first yamux stream (carries Noise handshake)
    let yamux_stream = match accepted.next_inbound().await {
        Some(Ok(s)) => s,
        Some(Err(e)) => {
            pending.write().await.remove(&bond_id);
            return Err(fp_transport::Error::UnexpectedResult(format!("yamux accept: {}", e)));
        }
        None => {
            pending.write().await.remove(&bond_id);
            return Err(fp_transport::Error::UnexpectedResult("yamux closed".into()));
        }
    };

    let health = Arc::new(ConnHealth::new(config));
    group.add_stream(0, health, yamux_stream).await;

    // Drive primary yamux
    tokio::spawn(async move { while let Some(Ok(_)) = accepted.next_inbound().await {} });

    // Send BondGroup to listener -- it will read the first packet itself
    if primary_tx.send((group, peer_addr.ip())).await.is_err() {
        tracing::warn!("Primary accept channel closed, dropping bond group");
    }

    tracing::info!(%peer_addr, "Primary bond connection ready");
    Ok(())
}
