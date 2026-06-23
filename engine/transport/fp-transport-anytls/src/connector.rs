//! Implements fp-transport Connector/Listener/TransportSender/TransportReceiver traits.

use crate::acceptor::AnytlsAcceptor;
use crate::anytls_util::hash_password;
use crate::bond::{BondedReceiver, BondedSender};
use crate::config::AnytlsConfig;
use fp_transport::{AcceptResponse, Config, Listener, SenderAndReceiver};
use std::net::SocketAddr;
use std::sync::Arc;

#[allow(clippy::disallowed_types)]
static ANYTLS_CONFIG: std::sync::RwLock<Option<AnytlsConfig>> = std::sync::RwLock::new(None);

/// Set the AnyTLS config. Can be called multiple times (e.g., when switching servers).
#[allow(dead_code)]
pub fn set_anytls_config(config: AnytlsConfig) {
    if let Ok(mut guard) = ANYTLS_CONFIG.write() {
        *guard = Some(config);
    }
}

/// Snapshot the currently configured AnyTLS config (defaulted if unset).
pub fn get_config_cloned() -> AnytlsConfig {
    ANYTLS_CONFIG
        .read()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default()
}

/// Build a TLS server config + password hash from an `AnytlsConfig`.
///
/// Shared between the per-port AnyTLS listener and the demux listener so both
/// derive identical TLS acceptor + auth material from the same source.
pub fn build_server_tls(
    anytls_cfg: &AnytlsConfig,
) -> Result<(Arc<tokio_rustls::TlsAcceptor>, [u8; 32]), fp_transport::Error> {
    let tls_config = if let (Some(cert), Some(key)) = (&anytls_cfg.cert_path, &anytls_cfg.key_path) {
        crate::anytls_util::create_server_config_from_files(cert, key)
            .map_err(|e| fp_transport::Error::UnexpectedResult(format!("TLS config: {}", e)))?
    } else {
        crate::anytls_util::create_server_config()
            .map_err(|e| fp_transport::Error::UnexpectedResult(format!("TLS config: {}", e)))?
    };
    let tls_acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(tls_config));
    let password_hash = hash_password(&anytls_cfg.password);
    Ok((tls_acceptor, password_hash))
}

#[derive(Debug)]
pub struct AnytlsConnector;

#[async_trait::async_trait]
impl fp_transport::Connector for AnytlsConnector {
    async fn bind(config: Config) -> Result<Box<dyn Listener>, fp_transport::Error> {
        let anytls_cfg = get_config_cloned();
        let addr = SocketAddr::new(config.endpoint, config.port);

        let (tls_acceptor, password_hash) = build_server_tls(&anytls_cfg)?;
        let acceptor = Arc::new(AnytlsAcceptor::new(tls_acceptor, password_hash, anytls_cfg));

        let tcp_listener = Arc::new(
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(fp_transport::Error::IO)?,
        );

        tracing::info!(%addr, "AnyTLS listener bound");

        // Shutdown notifier: dropped Listener triggers shutdown of accept_loop.
        let shutdown = Arc::new(tokio::sync::Notify::new());

        // Spawn ONE acceptor task that handles ALL incoming connections concurrently.
        // It only accepts raw TCP streams and feeds them into the AnytlsAcceptor;
        // the AnytlsAcceptor spawns a per-connection task (HOL-safe) for each.
        let listener_clone = tcp_listener.clone();
        let acceptor_clone = acceptor.clone();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            accept_loop(listener_clone, acceptor_clone, shutdown_clone).await;
        });

        Ok(Box::new(AnytlsListener { acceptor, shutdown }))
    }

    async fn connect(config: Config) -> Result<SenderAndReceiver, fp_transport::Error> {
        let anytls_cfg = get_config_cloned();
        let addr = SocketAddr::new(config.endpoint, config.port);

        let tls_config = crate::anytls_util::create_client_config(anytls_cfg.insecure_skip_verify)
            .map_err(|e| fp_transport::Error::UnexpectedResult(format!("TLS config: {}", e)))?;
        let tls_connector = Arc::new(tokio_rustls::TlsConnector::from(tls_config));

        let group = crate::bond::build_client_bond(&anytls_cfg, addr, &tls_connector).await?;

        let n = group.alive_count().await;
        tracing::info!(bond_connections = n, "AnyTLS client connected");

        let sender: Box<dyn fp_transport::TransportSender> = Box::new(BondedSender { group: group.clone() });
        let receiver: Box<dyn fp_transport::TransportReceiver> = Box::new(BondedReceiver { group });

        Ok((sender, receiver))
    }
}

// ── Listener that receives fully-ready bonds (first packet already read) ──

/// Thin wrapper: owns a TcpListener (whose accept_loop feeds the acceptor) plus
/// the shared `AnytlsAcceptor` that performs TLS+auth+bond+HOL-safe first-packet
/// reads and exposes the ready queue.
struct AnytlsListener {
    acceptor: Arc<AnytlsAcceptor>,
    shutdown: Arc<tokio::sync::Notify>,
}

impl Drop for AnytlsListener {
    fn drop(&mut self) {
        // Signal the accept_loop task to stop accepting new TCP connections.
        self.shutdown.notify_waiters();
    }
}

#[async_trait::async_trait]
impl Listener for AnytlsListener {
    async fn accept(
        &self,
        closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    ) -> Result<AcceptResponse, fp_transport::Error> {
        // accept() only pops connections whose first Noise packet has ALREADY
        // been read (by a dedicated per-connection task inside the acceptor).
        // It never blocks on a single group.recv(), so a connection that never
        // sends its first packet can no longer wedge the listener.
        tokio::select! {
            _ = closer.recv() => {
                tracing::info!("anytls listener closed, exiting accept loop");
                // Signal accept_loop too, so the underlying TCP listener stops.
                self.shutdown.notify_waiters();
                Err(fp_transport::Error::ListenerHasBeenClosed)
            }
            result = self.acceptor.accept_ready() => result,
        }
    }
}

// ── Accept loop: runs in a dedicated task, feeds streams into the acceptor ──

async fn accept_loop(
    tcp_listener: Arc<tokio::net::TcpListener>,
    acceptor: Arc<AnytlsAcceptor>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    // Exponential backoff state for accept() errors (FD exhaustion etc.)
    let mut backoff_ms: u64 = 100;
    let mut error_streak: u32 = 0;
    loop {
        let accept_result = tokio::select! {
            _ = shutdown.notified() => {
                tracing::info!("anytls accept_loop: shutdown signal received, exiting");
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
                    tracing::error!(error_streak, ?e, "anytls accept: persistent failure");
                } else {
                    tracing::warn!(?e, backoff_ms, "anytls accept error, backing off");
                }
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(1000);
                continue;
            }
        };

        // Hand the established stream to the acceptor, which spawns a
        // per-connection task — never blocks the accept loop (no HOL blocking).
        acceptor.feed_stream(tcp, peer_addr);
    }
}
