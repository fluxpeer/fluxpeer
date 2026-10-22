//! Single managed connection: TCP -> bond header -> yamux
//!
//! yamux Connection is driven by a dedicated task. Stream open requests are sent
//! via channel to avoid Mutex contention on the Connection.

use crate::config::TcpBondConfig;
use crate::health::ConnHealth;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_util::compat::TokioAsyncReadCompatExt;

type ClientYamuxConn = yamux::Connection<tokio_util::compat::Compat<TcpStream>>;
type ServerYamuxConn = yamux::Connection<tokio_util::compat::Compat<TcpStream>>;

// -- Bond header --

pub fn generate_bond_id() -> [u8; 16] {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

// -- Channel-based yamux driver --

type OpenStreamReq = oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>;

/// Drives a yamux Connection in a dedicated task.
/// Handles both inbound streams and outbound open requests via channel.
fn spawn_yamux_driver(
    mut conn: ClientYamuxConn,
    mut open_rx: tokio::sync::mpsc::Receiver<OpenStreamReq>,
    health: Arc<ConnHealth>,
    id: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Process all pending open_stream requests first
            while let Ok(reply_tx) = open_rx.try_recv() {
                let result = poll_fn(|cx| conn.poll_new_outbound(cx)).await;
                let _ = reply_tx.send(result);
            }

            // Now poll: either a new open request arrives, or an inbound stream, or connection closes
            tokio::select! {
                biased;
                Some(reply_tx) = open_rx.recv() => {
                    let result = poll_fn(|cx| conn.poll_new_outbound(cx)).await;
                    let _ = reply_tx.send(result);
                }
                result = poll_fn(|cx| conn.poll_next_inbound(cx)) => {
                    match result {
                        Some(Ok(_stream)) => {
                            // Server-initiated stream on client side -- unusual, drop it
                        }
                        Some(Err(e)) => {
                            tracing::error!(id, "yamux error: {}", e);
                            health.record_failure();
                            break;
                        }
                        None => {
                            tracing::debug!(id, "yamux connection closed");
                            health.record_failure();
                            break;
                        }
                    }
                }
            }
        }
    })
}

/// Client-side TCP+yamux connection
pub struct ManagedConnection {
    pub link_session: Option<fp_transport::link::Session>,
    pub id: usize,
    pub health: Arc<ConnHealth>,
    open_tx: tokio::sync::mpsc::Sender<OpenStreamReq>,
    _driver: tokio::task::JoinHandle<()>,
}

/// Server-side accepted connection
#[allow(dead_code)]
pub struct AcceptedConnection {
    pub yamux_conn: ServerYamuxConn,
    pub bond_id: [u8; 16],
    pub bond_total: u8,
    pub link_index: u32,
    pub link_session: Option<fp_transport::link::Session>,
    pub peer_addr: SocketAddr,
}

impl AcceptedConnection {
    pub async fn next_inbound(&mut self) -> Option<Result<yamux::Stream, yamux::ConnectionError>> {
        poll_fn(|cx| self.yamux_conn.poll_next_inbound(cx)).await
    }
}

impl ManagedConnection {
    pub async fn connect_authenticated(
        id: usize,
        addr: SocketAddr,
        config: &TcpBondConfig,
        bond_id: &[u8; 16],
        authenticator: Option<fp_transport::link::Authenticator>,
    ) -> Result<Self, fp_transport::Error> {
        let health = Arc::new(ConnHealth::new(config));
        let total = config.effective_bond_connections() as u8;

        // Protect-before-connect so this link egresses the real interface, not the
        // VPN tun, when running under a mobile VpnService (no-op on desktop/server).
        let tcp = fp_transport::connect_tcp(addr).await.map_err(fp_transport::Error::IO)?;
        tcp.set_nodelay(true).map_err(fp_transport::Error::IO)?;

        // Set TCP keepalive via socket2
        let sock = socket2::Socket::from(tcp.into_std().map_err(fp_transport::Error::IO)?);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10));
        sock.set_tcp_keepalive(&keepalive).map_err(fp_transport::Error::IO)?;
        sock.set_keepalive(true).map_err(fp_transport::Error::IO)?;
        let std_tcp = std::net::TcpStream::from(sock);
        std_tcp.set_nonblocking(true).map_err(fp_transport::Error::IO)?;
        let mut tcp = TcpStream::from_std(std_tcp).map_err(fp_transport::Error::IO)?;

        // Write bond header directly on raw TCP
        fp_transport::link::write_header(&mut tcp, bond_id, total, id, authenticator.is_some())
            .await
            .map_err(fp_transport::Error::IO)?;

        let link_session = if let Some(auth) = &authenticator {
            Some(auth.client(&mut tcp, *bond_id, u32::try_from(id).map_err(|_| fp_transport::Error::IO(fp_transport::link::denied("link index exhausted")))?).await.map_err(fp_transport::Error::IO)?)
        } else { None };

        let compat_stream = tcp.compat();
        let yamux_conn = yamux::Connection::new(compat_stream, yamux::Config::default(), yamux::Mode::Client);

        let (open_tx, open_rx) = tokio::sync::mpsc::channel(128);
        let driver = spawn_yamux_driver(yamux_conn, open_rx, health.clone(), id);

        tracing::info!(id, "TCP bond connection established");

        Ok(Self {
            id,
            health,
            open_tx,
            _driver: driver,
            link_session,
        })
    }

    pub async fn open_stream(&self) -> Result<yamux::Stream, fp_transport::Error> {
        self.health.increment_streams();
        let (tx, rx) = oneshot::channel();
        self.open_tx.send(tx).await.map_err(|_| {
            self.health.decrement_streams();
            fp_transport::Error::UnexpectedResult("yamux driver closed".into())
        })?;
        rx.await
            .map_err(|_| {
                self.health.decrement_streams();
                fp_transport::Error::UnexpectedResult("yamux driver dropped reply".into())
            })?
            .map_err(|e| {
                self.health.decrement_streams();
                fp_transport::Error::UnexpectedResult(format!("yamux open_stream: {}", e))
            })
    }

    pub async fn ping(&self, timeout: Duration) -> Result<(), fp_transport::Error> {
        self.health.mark_ping_sent().await;
        match tokio::time::timeout(timeout, self.open_stream()).await {
            Ok(Ok(stream)) => {
                self.health.decrement_streams();
                drop(stream);
                self.health.process_pong().await;
                Ok(())
            }
            Ok(Err(e)) => {
                self.health.record_failure();
                Err(e)
            }
            Err(_) => {
                self.health.record_failure();
                Err(fp_transport::Error::UnexpectedResult("ping timeout".into()))
            }
        }
    }
}

pub async fn accept_server_connection(mut tcp: TcpStream, authenticator: Option<&fp_transport::link::Authenticator>) -> Result<AcceptedConnection, fp_transport::Error> {
    let peer_addr = tcp.peer_addr().map_err(fp_transport::Error::IO)?;
    tcp.set_nodelay(true).map_err(fp_transport::Error::IO)?;

    let (bond_id, bond_total, link_index) = fp_transport::link::read_header(&mut tcp, authenticator.is_some()).await.map_err(fp_transport::Error::IO)?;
    let link_session = if let Some(auth) = authenticator { Some(auth.server(&mut tcp, bond_id, link_index).await.map_err(fp_transport::Error::IO)?) } else { None };

    let compat_stream = tcp.compat();
    let yamux_conn = yamux::Connection::new(compat_stream, yamux::Config::default(), yamux::Mode::Server);

    Ok(AcceptedConnection {
        yamux_conn,
        bond_id,
        bond_total,
        link_index,
        link_session,
        peer_addr,
    })
}
