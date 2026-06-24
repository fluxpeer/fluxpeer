//! Relay network layer: drives the wire protocol over a byte stream and the
//! [`Hub`] router. DERP-style, addressed by Curve25519
//! pubkey, payloads opaque (never decrypted).
//!
//! [`RelayServer::serve_conn`] is generic over any `AsyncRead + AsyncWrite`
//! stream, so the same logic serves a plain TCP socket today and an anytls/443
//! connection later (just wrap the stream). [`RelayServer::serve`] is the TCP
//! accept loop. Duties implemented: handshake + pluggable auth, forward-by-pubkey,
//! Ping→Pong, PeerGone, per-client inbound rate limit, bounded send queues.

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Drop a plain-TCP client that hasn't sent ANY frame (not even its 3s keepalive
/// Ping) for this long. A half-open TCP (peer force-killed, NAT dropped the mapping)
/// otherwise leaves the read blocked forever, pinning a stale pubkey registration so
/// returning frames queue to a dead socket. 20s tolerates ~6 missed keepalives.
const PLAIN_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(20);

use fp_transport_tcp_bond::TcpBondConnector;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::hub::{DEFAULT_QUEUE_CAP, Hub, Routed};
use crate::proto::{Error as ProtoError, Frame, PublicKey};
use crate::ratelimit::TokenBucket;

/// Relay wire-protocol version advertised in `ServerInfo`.
pub const RELAY_PROTOCOL_VERSION: u32 = 1;

/// Server tuning.
#[derive(Debug, Clone)]
pub struct Config {
    pub protocol_version: u32,
    /// Per-client outbound send-queue depth (drop-on-full).
    pub queue_cap: usize,
    /// Sustained inbound `SendPacket` frames/sec per client.
    pub rate_per_sec: u32,
    /// Inbound burst allowance.
    pub burst: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: RELAY_PROTOCOL_VERSION,
            queue_cap: DEFAULT_QUEUE_CAP,
            // Per-client inbound frame/sec cap (DoS guard). The old 5_000 fps
            // throttled a real data plane to ~56 Mbit/s (5_000 × ~1400 B); a relay
            // forwarding VPN traffic needs line rate. 200k fps ≈ 2.2 Gbit/s at MTU;
            // env FLUXPEER_RELAY_RATE_PER_SEC / _BURST tune it (see serve_from_env).
            rate_per_sec: 200_000,
            burst: 400_000,
        }
    }
}

/// Decides whether a client may use the relay. Real deployments scope this to a
/// network/invite via the control-server relay directory; the default allows any
/// client speaking a compatible protocol version.
pub trait Auth: Send + Sync {
    fn authorize(&self, pubkey: &PublicKey, protocol_version: u32) -> bool;
}

/// Accept any client whose protocol version is at least `min_version`.
pub struct AllowAll {
    pub min_version: u32,
}

impl Default for AllowAll {
    fn default() -> Self {
        Self {
            min_version: RELAY_PROTOCOL_VERSION,
        }
    }
}

impl Auth for AllowAll {
    fn authorize(&self, _pubkey: &PublicKey, protocol_version: u32) -> bool {
        protocol_version >= self.min_version
    }
}

pub struct RelayServer {
    hub: Arc<Hub>,
    cfg: Config,
    auth: Arc<dyn Auth>,
}

impl RelayServer {
    pub fn new(cfg: Config, auth: Arc<dyn Auth>) -> Self {
        Self {
            hub: Arc::new(Hub::with_capacity(cfg.queue_cap)),
            cfg,
            auth,
        }
    }

    pub fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    /// TCP accept loop: one task per connection. Runs until `listener` errors.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        tracing::info!(
            version = self.cfg.protocol_version,
            "relay-server accepting connections"
        );
        loop {
            let (stream, peer) = listener.accept().await?;
            let _ = stream.set_nodelay(true);
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.serve_conn(stream).await {
                    tracing::debug!(%peer, error = %e, "relay connection ended");
                }
            });
        }
    }

    /// Accept clients over **AnyTLS** (TLS 1.3 + anti-fingerprint + yamux — the
    /// censorship-resistant 443 transport), bonded: each connection aggregates N
    /// TLS yamux links (health-weighted + auto-reconnect) and is message-oriented,
    /// exactly like the TCP-bond path. `node_id` seeds the shared AnyTLS password
    /// (process-global, read by `AnytlsConnector::bind`). The forwarding core is
    /// the shared [`Self::serve_bonded_conn`] pump.
    pub async fn serve_anytls(self: Arc<Self>, config: fp_transport::Config, node_id: String) -> std::io::Result<()> {
        fp_transport_anytls::set_anytls_config(fp_transport_anytls::AnytlsConfig::with_node_id(&node_id));
        let listener = <fp_transport_anytls::AnytlsConnector as fp_transport::Connector>::bind(config)
            .await
            .map_err(std::io::Error::other)?;
        // Keep `_keep` alive so the listener's `closer` never fires (the process
        // lifetime owns the listener; we never explicitly close from here).
        let (_keep, mut closer) = tokio::sync::mpsc::unbounded_channel::<()>();
        tracing::info!(
            version = self.cfg.protocol_version,
            "relay-server accepting AnyTLS (bonded) connections"
        );
        loop {
            match listener.accept(&mut closer).await {
                Ok(resp) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.serve_bonded_conn(resp).await {
                            tracing::debug!(error = %e, "anytls relay connection ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "anytls accept failed, stopping listener");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Accept clients over the **TCP-bond** transport: each connection aggregates N
    /// TCP links (health-weighted + auto-reconnect) and is message-oriented — every
    /// `recv` yields one whole [`Frame`], every `send` writes one. The forwarding
    /// core is identical to [`Self::serve_conn`] (handshake → hub register → pump),
    /// but over the bond's sender/receiver instead of a byte stream.
    pub async fn serve_bonded(self: Arc<Self>, config: fp_transport::Config) -> std::io::Result<()> {
        let listener = <TcpBondConnector as fp_transport::Connector>::bind(config)
            .await
            .map_err(std::io::Error::other)?;
        // Keep `_keep` alive so the listener's `closer` never fires (we never
        // explicitly close from here — the process lifetime owns the listener).
        let (_keep, mut closer) = tokio::sync::mpsc::unbounded_channel::<()>();
        tracing::info!(
            version = self.cfg.protocol_version,
            "relay-server accepting TCP-bond connections"
        );
        loop {
            match listener.accept(&mut closer).await {
                Ok(resp) => {
                    let this = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = this.serve_bonded_conn(resp).await {
                            tracing::debug!(error = %e, "tcp-bond relay connection ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "tcp-bond accept failed, stopping listener");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Drive one bonded client connection. The first packet (already read by the
    /// bond `accept`) must be `ClientInfo`; then mirror the [`Self::serve_conn`]
    /// pump over the message-oriented bond sender/receiver.
    async fn serve_bonded_conn(&self, resp: fp_transport::AcceptResponse) -> std::io::Result<()> {
        let mut sender = resp.sender;
        let mut receiver = resp.receiver;

        // 1. Handshake: the first packet must be ClientInfo.
        let pubkey = match Frame::decode(&resp.packet) {
            Ok((
                Frame::ClientInfo {
                    pubkey,
                    protocol_version,
                },
                _,
            )) => {
                if !self.auth.authorize(&pubkey, protocol_version) {
                    tracing::debug!("tcp-bond relay auth rejected (version {protocol_version})");
                    return Ok(());
                }
                pubkey
            }
            _ => return Err(invalid("expected ClientInfo handshake")),
        };

        // 2. Acknowledge with ServerInfo.
        sender
            .send(
                Frame::ServerInfo {
                    protocol_version: self.cfg.protocol_version,
                }
                .encode(),
            )
            .await
            .map_err(std::io::Error::other)?;

        // 3. Register; `self_tx` carries self-addressed replies (Pong/PeerGone).
        let (self_tx, mut out_rx) = self.hub.connect(pubkey);
        let mut bucket = TokenBucket::new(self.cfg.rate_per_sec, self.cfg.burst, Instant::now());

        // 4. Pump: interleave outbound delivery and inbound routing.
        let reason = loop {
            tokio::select! {
                outbound = out_rx.recv() => match outbound {
                    Some(frame) => {
                        if sender.send(frame.encode()).await.is_err() {
                            break "write failed";
                        }
                    }
                    None => break "outbound closed",
                },
                inbound = tokio::time::timeout(PLAIN_TCP_IDLE_TIMEOUT, receiver.recv()) => match inbound {
                    Ok(Ok(bytes)) => match Frame::decode(&bytes) {
                        Ok((frame, _)) => self.handle_inbound(pubkey, frame, &self_tx, &mut bucket),
                        Err(_) => break "protocol error",
                    },
                    Ok(Err(_)) => break "client closed",
                    // No frame (not even a 3s keepalive Ping) for the idle window: a
                    // silently-dead bonded peer (dropped NAT mapping / force-kill) that
                    // the bond layer never surfaces as an error. Drop it so its hub
                    // registration is freed instead of black-holing traffic (finding 2).
                    Err(_) => break "idle timeout",
                },
            }
        };

        // 5. Cleanup (only if this session is still the registered one).
        self.hub.disconnect_session(&pubkey, &self_tx);
        tracing::debug!(reason, "tcp-bond relay session closed");
        Ok(())
    }

    /// Drive one client connection over any byte stream.
    pub async fn serve_conn<S>(&self, stream: S) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (rd, mut wr) = tokio::io::split(stream);
        let mut reader = FrameReader::new(rd);

        // 1. Handshake: the first frame must be ClientInfo.
        let pubkey = match reader.next_frame().await? {
            Some(Frame::ClientInfo {
                pubkey,
                protocol_version,
            }) => {
                if !self.auth.authorize(&pubkey, protocol_version) {
                    tracing::debug!("relay auth rejected (version {protocol_version})");
                    return Ok(());
                }
                pubkey
            }
            _ => return Err(invalid("expected ClientInfo handshake")),
        };

        // 2. Acknowledge with ServerInfo.
        wr.write_all(
            &Frame::ServerInfo {
                protocol_version: self.cfg.protocol_version,
            }
            .encode(),
        )
        .await?;

        // 3. Register; `self_tx` lets us queue self-addressed replies (Pong/PeerGone)
        // through the same single write path as relayed frames.
        let (self_tx, mut out_rx) = self.hub.connect(pubkey);
        let mut bucket = TokenBucket::new(self.cfg.rate_per_sec, self.cfg.burst, Instant::now());

        // 4. Pump: interleave outbound delivery and inbound routing.
        let reason = loop {
            tokio::select! {
                outbound = out_rx.recv() => match outbound {
                    Some(frame) => {
                        if wr.write_all(&frame.encode()).await.is_err() {
                            break "write failed";
                        }
                    }
                    None => break "outbound closed",
                },
                inbound = tokio::time::timeout(PLAIN_TCP_IDLE_TIMEOUT, reader.next_frame()) => match inbound {
                    Ok(Ok(Some(frame))) => self.handle_inbound(pubkey, frame, &self_tx, &mut bucket),
                    Ok(Ok(None)) => break "client closed",
                    Ok(Err(_)) => break "protocol/io error",
                    // No frame (not even a keepalive Ping) for the idle window → the
                    // client is gone/half-open; drop it so its registration is freed.
                    Err(_) => break "idle timeout",
                },
            }
        };

        // 5. Cleanup (only if this session is still the registered one).
        self.hub.disconnect_session(&pubkey, &self_tx);
        tracing::debug!(reason, "relay session closed");
        Ok(())
    }

    fn handle_inbound(
        &self,
        from: PublicKey,
        frame: Frame,
        self_tx: &tokio::sync::mpsc::Sender<Frame>,
        bucket: &mut TokenBucket,
    ) {
        match frame {
            Frame::SendPacket { .. } => {
                if !bucket.allow(Instant::now()) {
                    return; // rate-limited: drop silently (best-effort transport)
                }
                if let Routed::PeerGone(dst) = self.hub.route(from, frame) {
                    let _ = self_tx.try_send(Frame::PeerGone { pubkey: dst });
                }
            }
            Frame::Ping { data } => {
                let _ = self_tx.try_send(Frame::Pong { data });
            }
            // Pong (RTT tracking later), repeated ClientInfo, or server-only frames: ignore.
            _ => {}
        }
    }
}

fn invalid(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

/// Reads length-prefixed [`Frame`]s from an `AsyncRead`, buffering partial reads.
struct FrameReader<R> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(8 * 1024),
        }
    }

    /// Next complete frame, or `None` at clean EOF. A malformed/oversized frame
    /// is a protocol error (`InvalidData`); a truncated frame at EOF is `UnexpectedEof`.
    async fn next_frame(&mut self) -> std::io::Result<Option<Frame>> {
        loop {
            match Frame::decode(&self.buf) {
                Ok((frame, n)) => {
                    self.buf.drain(..n);
                    return Ok(Some(frame));
                }
                Err(ProtoError::ShortBuffer { .. }) => { /* need more bytes */ }
                Err(e) => return Err(invalid_owned(e)),
            }
            let mut tmp = [0u8; 8 * 1024];
            let n = self.inner.read(&mut tmp).await?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "partial frame at EOF",
                    ))
                };
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

fn invalid_owned(e: ProtoError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::net::TcpStream;

    fn key(b: u8) -> PublicKey {
        [b; 32]
    }

    async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, f: Frame) {
        s.write_all(&f.encode()).await.unwrap();
    }

    /// Read exactly one frame (header then body) from a stream.
    async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> Frame {
        let mut hdr = [0u8; 5];
        s.read_exact(&mut hdr).await.unwrap();
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        let mut full = hdr.to_vec();
        full.resize(5 + len, 0);
        s.read_exact(&mut full[5..]).await.unwrap();
        Frame::decode(&full).unwrap().0
    }

    async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, k: PublicKey) {
        write_frame(
            s,
            Frame::ClientInfo {
                pubkey: k,
                protocol_version: RELAY_PROTOCOL_VERSION,
            },
        )
        .await;
        assert_eq!(
            read_frame(s).await,
            Frame::ServerInfo {
                protocol_version: RELAY_PROTOCOL_VERSION
            }
        );
    }

    async fn start_server() -> std::net::SocketAddr {
        let server = Arc::new(RelayServer::new(Config::default(), Arc::new(AllowAll::default())));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));
        addr
    }

    #[tokio::test]
    async fn relays_packet_between_two_clients_over_tcp() {
        let addr = start_server().await;
        let (a, b) = (key(0xAA), key(0xBB));

        let mut ca = TcpStream::connect(addr).await.unwrap();
        handshake(&mut ca, a).await;
        let mut cb = TcpStream::connect(addr).await.unwrap();
        handshake(&mut cb, b).await;

        // A → B
        write_frame(
            &mut ca,
            Frame::SendPacket {
                dst: b,
                payload: vec![1, 2, 3, 4],
            },
        )
        .await;
        assert_eq!(
            read_frame(&mut cb).await,
            Frame::RecvPacket {
                src: a,
                payload: vec![1, 2, 3, 4]
            }
        );

        // B → A (bidirectional)
        write_frame(
            &mut cb,
            Frame::SendPacket {
                dst: a,
                payload: vec![9],
            },
        )
        .await;
        assert_eq!(
            read_frame(&mut ca).await,
            Frame::RecvPacket {
                src: b,
                payload: vec![9]
            }
        );
    }

    #[tokio::test]
    async fn ping_gets_pong() {
        let addr = start_server().await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        handshake(&mut c, key(1)).await;
        write_frame(
            &mut c,
            Frame::Ping {
                data: [1, 2, 3, 4, 5, 6, 7, 8],
            },
        )
        .await;
        assert_eq!(
            read_frame(&mut c).await,
            Frame::Pong {
                data: [1, 2, 3, 4, 5, 6, 7, 8]
            }
        );
    }

    #[tokio::test]
    async fn send_to_absent_peer_yields_peer_gone() {
        let addr = start_server().await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        handshake(&mut c, key(1)).await;
        write_frame(
            &mut c,
            Frame::SendPacket {
                dst: key(0xEE),
                payload: vec![0],
            },
        )
        .await;
        assert_eq!(read_frame(&mut c).await, Frame::PeerGone { pubkey: key(0xEE) });
    }

    #[tokio::test]
    async fn opaque_payload_is_forwarded_verbatim() {
        // The relay must not interpret payloads (wg-encrypted) — forward byte-exact.
        let addr = start_server().await;
        let (a, b) = (key(3), key(4));
        let mut ca = TcpStream::connect(addr).await.unwrap();
        handshake(&mut ca, a).await;
        let mut cb = TcpStream::connect(addr).await.unwrap();
        handshake(&mut cb, b).await;
        let blob: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        write_frame(
            &mut ca,
            Frame::SendPacket {
                dst: b,
                payload: blob.clone(),
            },
        )
        .await;
        assert_eq!(read_frame(&mut cb).await, Frame::RecvPacket { src: a, payload: blob });
    }

    #[tokio::test]
    async fn non_handshake_first_frame_is_rejected() {
        let addr = start_server().await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        // send a SendPacket before any ClientInfo → server closes the connection
        write_frame(
            &mut c,
            Frame::SendPacket {
                dst: key(2),
                payload: vec![1],
            },
        )
        .await;
        let mut buf = [0u8; 1];
        // server should drop us: read returns 0 (EOF)
        assert_eq!(c.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn auth_rejects_old_protocol_version() {
        let server = Arc::new(RelayServer::new(
            Config::default(),
            Arc::new(AllowAll { min_version: 2 }),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));

        let mut c = TcpStream::connect(addr).await.unwrap();
        write_frame(
            &mut c,
            Frame::ClientInfo {
                pubkey: key(1),
                protocol_version: 1,
            },
        )
        .await;
        let mut buf = [0u8; 1];
        assert_eq!(
            c.read(&mut buf).await.unwrap(),
            0,
            "rejected client gets closed, no ServerInfo"
        );
    }
}
