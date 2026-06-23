//! Single-stream byte-pipe over the AnyTLS transport (TLS 1.3 + AnyTLS auth +
//! yamux). Exposes a plain tokio `AsyncRead + AsyncWrite`, so stream-based
//! callers (e.g. the relay-server's `serve_conn`) can run unchanged over an
//! anti-fingerprinting 443 transport instead of plain TCP.
//!
//! Both ends derive the AnyTLS password from a shared `node_id`; the TLS cert is
//! self-signed (auth is at the AnyTLS/Noise layer, and relayed payloads are
//! wg-encrypted) so clients verify with `insecure_skip_verify`.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

use crate::anytls_util::{create_client_config, create_server_config, hash_password};
use crate::config::AnytlsConfig;
use crate::conn::{ManagedConnection, accept_server_connection, generate_bond_id};
use fp_transport::Error;

/// A bidirectional AnyTLS byte stream (one yamux substream). Owns whatever keeps
/// the underlying connection driver alive for as long as the stream is held.
pub struct AnytlsStream {
    stream: Compat<yamux::Stream>,
    _keepalive: KeepAlive,
}

/// RAII guard that keeps the underlying yamux driver alive for the lifetime of
/// the stream, and tears it down on drop.
enum KeepAlive {
    /// Client: the managed connection owns the yamux driver task.
    Client(ManagedConnection),
    /// Server: a task that keeps polling the yamux connection forward.
    Server(tokio::task::JoinHandle<()>),
}

impl Drop for KeepAlive {
    fn drop(&mut self) {
        match self {
            // Touch the connection so it lives until here; its own Drop cleans up.
            KeepAlive::Client(c) => {
                let _ = c.id;
            }
            // Stop driving the server-side yamux connection.
            KeepAlive::Server(h) => h.abort(),
        }
    }
}

impl AsyncRead for AnytlsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AnytlsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// Connect to an AnyTLS server at `addr` and open a byte stream. `node_id` is the
/// shared secret both ends derive the AnyTLS password from.
pub async fn connect_stream(addr: SocketAddr, node_id: &str) -> Result<AnytlsStream, Error> {
    let cfg = AnytlsConfig::with_node_id(node_id);
    let tls = create_client_config(cfg.insecure_skip_verify)
        .map_err(|e| Error::UnexpectedResult(format!("client TLS: {e}")))?;
    let connector = tokio_rustls::TlsConnector::from(tls);
    let bond_id = generate_bond_id();
    let cws = ManagedConnection::connect(0, addr, &cfg, &connector, &bond_id).await?;
    Ok(AnytlsStream {
        stream: cws.stream.compat(),
        _keepalive: KeepAlive::Client(cws.conn),
    })
}

/// Server-side AnyTLS acceptor: wraps inbound TCP connections into byte streams.
pub struct AnytlsListener {
    tls_acceptor: Arc<TlsAcceptor>,
    password_hash: [u8; 32],
}

impl AnytlsListener {
    /// Build an acceptor for `node_id` (self-signed cert, password from node_id).
    pub fn new(node_id: &str) -> Result<Self, Error> {
        let cfg = AnytlsConfig::with_node_id(node_id);
        let server_tls = create_server_config().map_err(|e| Error::UnexpectedResult(format!("server TLS: {e}")))?;
        Ok(Self {
            tls_acceptor: Arc::new(TlsAcceptor::from(server_tls)),
            password_hash: hash_password(&cfg.password),
        })
    }

    /// Complete the AnyTLS handshake on an accepted TCP socket and return the
    /// first yamux byte stream (a background task keeps the connection driven).
    pub async fn accept(&self, tcp: TcpStream) -> Result<AnytlsStream, Error> {
        let mut accepted = accept_server_connection(tcp, &self.tls_acceptor, &self.password_hash).await?;
        let stream = accepted
            .next_inbound()
            .await
            .ok_or_else(|| Error::UnexpectedResult("no inbound stream".into()))?
            .map_err(|e| Error::UnexpectedResult(format!("yamux: {e}")))?;
        let driver = tokio::spawn(async move { while let Some(Ok(_)) = accepted.next_inbound().await {} });
        Ok(AnytlsStream {
            stream: stream.compat(),
            _keepalive: KeepAlive::Server(driver),
        })
    }
}
