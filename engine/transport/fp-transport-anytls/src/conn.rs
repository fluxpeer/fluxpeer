//! Single managed connection: TCP → TLS 1.3 → AnyTLS auth → bond header → yamux
//!
//! yamux Connection is driven by a dedicated task. Stream open requests are sent
//! via channel to avoid Mutex contention on the Connection.

use crate::anytls_padding::PaddingFactory;
use crate::anytls_util::{hash_password, send_authentication};
use crate::config::AnytlsConfig;
use crate::health::ConnHealth;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_util::compat::TokioAsyncReadCompatExt;

type ClientYamuxConn = yamux::Connection<tokio_util::compat::Compat<tokio_rustls::client::TlsStream<TcpStream>>>;
type ServerYamuxConn = yamux::Connection<tokio_util::compat::Compat<tokio_rustls::server::TlsStream<TcpStream>>>;

// ── Bond header ──
const BOND_HEADER_LEN: usize = 18;
const BOND_VERSION: u8 = 1;

pub fn generate_bond_id() -> [u8; 16] {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

async fn write_bond_header<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    bond_id: &[u8; 16],
    total: u8,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; BOND_HEADER_LEN];
    buf[0] = BOND_VERSION;
    buf[1..17].copy_from_slice(bond_id);
    buf[17] = total;
    w.write_all(&buf).await?;
    w.flush().await
}

async fn read_bond_header<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<([u8; 16], u8), std::io::Error> {
    let mut buf = [0u8; BOND_HEADER_LEN];
    r.read_exact(&mut buf).await?;
    if buf[0] != BOND_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported bond version: {}", buf[0]),
        ));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&buf[1..17]);
    Ok((id, buf[17]))
}

// ── Channel-based yamux driver ──

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
        // Fuse both poll operations into a single poll_fn so that
        // poll_next_inbound (which drives Active::poll and flushes pending
        // SYN/data frames) is ALWAYS called on every poll cycle.
        // This prevents the race where poll_new_outbound creates a stream
        // but the SYN frame is never flushed because poll_next_inbound
        // was starved by biased select.
        enum Action {
            Continue,
            YamuxError(yamux::ConnectionError),
            YamuxClosed,
        }

        loop {
            let action = poll_fn(|cx| {
                // 1. Always drive the connection first — this flushes pending
                // SYN frames, data frames, and processes inbound frames.
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(_stream))) => {
                        // Server-initiated stream on client side — unusual, drop it
                        return Poll::Ready(Action::Continue);
                    }
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Action::YamuxError(e));
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Action::YamuxClosed);
                    }
                    Poll::Pending => {} // connection alive, continue
                }

                // 2. Check for open_stream requests (non-blocking)
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(reply_tx)) => {
                        // poll_new_outbound always returns Ready immediately
                        if let Poll::Ready(result) = conn.poll_new_outbound(cx) {
                            let _ = reply_tx.send(result);
                        }
                        // CRITICAL: flush the SYN frame RIGHT NOW within the
                        // same poll_fn call. poll_next_inbound drives
                        // Active::poll which transmits queued frames.
                        // Without this, the SYN sits in the queue until tokio
                        // re-schedules this task, causing a race with other
                        // connections' open_stream calls.
                        let _ = conn.poll_next_inbound(cx);
                        Poll::Ready(Action::Continue)
                    }
                    Poll::Ready(None) => {
                        // Channel closed, no more open requests expected
                        Poll::Pending
                    }
                    Poll::Pending => {
                        // Both are pending — wake when either has progress
                        Poll::Pending
                    }
                }
            })
            .await;

            match action {
                Action::Continue => continue,
                Action::YamuxError(e) => {
                    tracing::error!(id, "yamux error: {}", e);
                    health.record_failure();
                    break;
                }
                Action::YamuxClosed => {
                    tracing::debug!(id, "yamux connection closed");
                    health.record_failure();
                    break;
                }
            }
        }
    })
}

/// ManagedConnection + the yamux stream opened during connect().
pub struct ManagedConnectionWithStream {
    pub conn: ManagedConnection,
    pub stream: yamux::Stream,
}

/// Client-side TLS+yamux connection
pub struct ManagedConnection {
    pub id: usize,
    pub health: Arc<ConnHealth>,
    open_tx: tokio::sync::mpsc::Sender<OpenStreamReq>,
    _driver: tokio::task::JoinHandle<()>,
}

/// Server-side accepted connection
pub struct AcceptedConnection {
    pub yamux_conn: ServerYamuxConn,
    pub bond_id: [u8; 16],
    pub bond_total: u8,
    pub peer_addr: std::net::SocketAddr,
}

impl AcceptedConnection {
    pub async fn next_inbound(&mut self) -> Option<Result<yamux::Stream, yamux::ConnectionError>> {
        poll_fn(|cx| self.yamux_conn.poll_next_inbound(cx)).await
    }
}

impl ManagedConnection {
    pub async fn connect(
        id: usize,
        addr: SocketAddr,
        config: &AnytlsConfig,
        tls_connector: &tokio_rustls::TlsConnector,
        bond_id: &[u8; 16],
    ) -> Result<ManagedConnectionWithStream, fp_transport::Error> {
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
        let tcp = TcpStream::from_std(std_tcp).map_err(fp_transport::Error::IO)?;

        let server_name = ServerName::try_from(config.server_name.clone())
            .map_err(|e| fp_transport::Error::UnexpectedResult(format!("invalid SNI: {}", e)))?;
        let mut tls_stream = tls_connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| fp_transport::Error::UnexpectedResult(format!("TLS failed: {}", e)))?;

        let password_hash = hash_password(&config.password);
        let padding = PaddingFactory::default();
        send_authentication(&mut tls_stream, &password_hash, &padding)
            .await
            .map_err(|e| fp_transport::Error::UnexpectedResult(format!("auth failed: {}", e)))?;

        write_bond_header(&mut tls_stream, bond_id, total)
            .await
            .map_err(fp_transport::Error::IO)?;

        let compat_stream = tls_stream.compat();
        let mut yamux_conn = yamux::Connection::new(compat_stream, yamux::Config::default(), yamux::Mode::Client);

        // Open the yamux stream BEFORE spawning the driver.
        // This avoids the race where the driver's poll_next_inbound hasn't
        // flushed the SYN frame by the time build_client_bond proceeds.
        let stream = poll_fn(|cx| yamux_conn.poll_new_outbound(cx))
            .await
            .map_err(|e| fp_transport::Error::UnexpectedResult(format!("yamux open: {e}")))?;

        // Drive the connection to queue the SYN frame for writing.
        let _ = poll_fn(|cx| {
            let _ = yamux_conn.poll_next_inbound(cx);
            Poll::Ready(())
        })
        .await;
        // Yield to the tokio reactor so it can flush the TLS/TCP write buffers.
        // Without this, the SYN sits in the TLS write buffer because the reactor
        // hasn't had a chance to drive the socket write. A small sleep guarantees
        // the reactor runs and the SYN reaches the server.
        tokio::time::sleep(Duration::from_millis(5)).await;
        // Drive once more to process any response from the server.
        let _ = poll_fn(|cx| {
            let _ = yamux_conn.poll_next_inbound(cx);
            Poll::Ready(())
        })
        .await;

        let (open_tx, open_rx) = tokio::sync::mpsc::channel(128);
        let driver = spawn_yamux_driver(yamux_conn, open_rx, health.clone(), id);

        tracing::info!(id, "Bond connection established");

        Ok(ManagedConnectionWithStream {
            conn: Self {
                id,
                health,
                open_tx,
                _driver: driver,
            },
            stream,
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

    pub async fn ping(&self, timeout: std::time::Duration) -> Result<(), fp_transport::Error> {
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

pub async fn accept_server_connection(
    tcp: TcpStream,
    tls_acceptor: &tokio_rustls::TlsAcceptor,
    password_hash: &[u8; 32],
) -> Result<AcceptedConnection, fp_transport::Error> {
    let peer_addr = tcp.peer_addr().map_err(fp_transport::Error::IO)?;
    tcp.set_nodelay(true).map_err(fp_transport::Error::IO)?;

    let mut tls_stream = tls_acceptor
        .accept(tcp)
        .await
        .map_err(|e| fp_transport::Error::UnexpectedResult(format!("TLS accept: {}", e)))?;

    let padding = PaddingFactory::default();
    crate::anytls_util::authenticate_client(&mut tls_stream, password_hash, &padding)
        .await
        .map_err(|e| fp_transport::Error::UnexpectedResult(format!("auth: {}", e)))?;

    let (bond_id, bond_total) = read_bond_header(&mut tls_stream)
        .await
        .map_err(fp_transport::Error::IO)?;

    let compat_stream = tls_stream.compat();
    let yamux_conn = yamux::Connection::new(compat_stream, yamux::Config::default(), yamux::Mode::Server);

    Ok(AcceptedConnection {
        yamux_conn,
        bond_id,
        bond_total,
        peer_addr,
    })
}
