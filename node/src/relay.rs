//! Relay transport: one connection multiplexed by pubkey, with failover.

use std::net::SocketAddr;
use fp_crypto::x25519::{StaticSecret, PublicKey};
use fp_transport::link::LinkAuthenticator;
use fluxpeer_relay_server::auth::ClientAuth;
use std::time::Duration;

use fluxpeer_relay_server::proto::Frame as RelayFrame;
use fluxpeer_relay_server::server::RELAY_PROTOCOL_VERSION;
use fp_transport::{TransportReceiver, TransportSender};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Relay channels are keyed by peer pubkey so ONE relay connection multiplexes
/// every peer: inbound `(src, payload)`, outbound `(dst, payload)`.
pub(crate) type RelayIn = mpsc::Receiver<([u8; 32], Vec<u8>)>;
type RelayPacket = ([u8; 32], Vec<u8>);
type RelaySender = mpsc::Sender<RelayPacket>;
#[derive(Clone)]
pub(crate) struct RelayOut {
    sender: RelaySender,
    targets: tokio::sync::watch::Receiver<Vec<RelayTarget>>,
}
impl RelayOut {
    pub(crate) fn new(sender: RelaySender, targets: tokio::sync::watch::Receiver<Vec<RelayTarget>>) -> Self { Self { sender, targets } }
    pub(crate) fn available(&self) -> bool { !self.targets.borrow().is_empty() && !self.sender.is_closed() }
    pub(crate) fn try_send(&self, packet: RelayPacket) -> Result<(), mpsc::error::TrySendError<RelayPacket>> {
        self.sender.try_send(packet)
    }
}

/// Drive the relay protocol over a byte stream (TCP or AnyTLS): handshake, then
/// spawn reader/writer tasks keyed by peer pubkey. Returns keyed channels.
pub(crate) async fn connect_relay<S>(mut stream: S, auth: &ClientAuth) -> std::io::Result<(RelayIn, RelaySender)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let identity = auth.client(&mut stream, [0; 16], 0).await?;
    let own_pub = identity.peer();
    let (mut rd, mut wr) = tokio::io::split(stream);
    wr.write_all(
        &RelayFrame::ClientInfo {
            pubkey: own_pub,
            protocol_version: RELAY_PROTOCOL_VERSION,
        }
        .encode(),
    )
    .await?;
    let mut hdr = [0u8; 5];
    rd.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    // Bound the length a hostile/on-path relay can claim: without this the
    // `vec![0u8; len]` below would let it force a multi-GiB allocation (client OOM)
    // before any read. Mirror the server's own MAX_PACKET_SIZE+key cap.
    if len > fluxpeer_relay_server::proto::MAX_PACKET_SIZE + 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "relay ServerInfo frame too large",
        ));
    }
    let mut reply = hdr.to_vec(); reply.resize(5 + len, 0);
    rd.read_exact(reply.get_mut(5..).ok_or_else(|| std::io::Error::other("invalid relay header"))?).await?;
    validate_server_info(&reply)?;

    let (in_tx, in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    let (out_tx, mut out_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    // ONE task drives read + write + a 3s keepalive Ping. Unifying them means the
    // connection has a single lifetime: any of EOF, a write error, a failed
    // keepalive (dead relay, even when idle), or the app dropping `out_tx` ends the
    // task, drops `in_tx`, and closes `in_rx` — the supervisor's failover signal.
    tokio::spawn(async move {
        let _lease = fluxpeer_relay_server::auth::Lease(identity);
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let mut ka = tokio::time::interval(Duration::from_secs(3));
        ka.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ka.tick() => {
                    if wr.write_all(&RelayFrame::Ping { data: [0u8; 8] }.encode()).await.is_err() {
                        return;
                    }
                }
                out = out_rx.recv() => match out {
                    Some((dst, payload)) => {
                        if wr.write_all(&RelayFrame::SendPacket { dst, payload }.encode()).await.is_err() {
                            return;
                        }
                    }
                    None => return, // app dropped the sender → shut down
                },
                r = rd.read(&mut tmp) => match r {
                    Ok(0) | Err(_) => return,
                    Ok(k) => {
                        buf.extend_from_slice(&tmp[..k]);
                        loop {
                            match RelayFrame::decode(&buf) {
                                Ok((RelayFrame::RecvPacket { src, payload }, n)) => {
                                    buf.drain(..n);
                                    if in_tx.send((src, payload)).await.is_err() {
                                        return;
                                    }
                                }
                                Ok((_, n)) => {
                                    buf.drain(..n);
                                }
                                Err(_) => break,
                            }
                        }
                    }
                },
            }
        }
    });
    Ok((in_rx, out_tx))
}

/// Like [`connect_relay`] but over a message-oriented TCP-bond transport: each
/// `send`/`recv` carries one whole [`RelayFrame`], so we don't byte-buffer. The
/// bond aggregates N TCP links with health-weighting + auto-reconnect underneath.
pub(crate) async fn connect_relay_bonded(
    mut sender: Box<dyn TransportSender>,
    mut receiver: Box<dyn TransportReceiver>,
    own_pub: [u8; 32],
) -> std::io::Result<(RelayIn, RelaySender)> {
    let identity = sender.link_session().filter(|s| s.active() && s.peer() == own_pub)
        .ok_or_else(|| fp_transport::link::denied("relay requires authenticated bond"))?;
    sender
        .send(
            RelayFrame::ClientInfo {
                pubkey: own_pub,
                protocol_version: RELAY_PROTOCOL_VERSION,
            }
            .encode(),
        )
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let reply = receiver
        .recv()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    validate_server_info(&reply)?;

    let (in_tx, in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    let (out_tx, mut out_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    // ONE task drives read + write. Any of: a recv/send error, or the app dropping
    // `out_tx`, ends the task, drops `in_tx`, and closes `in_rx` — the supervisor's
    // failover signal. The bond handles keepalive/reconnect internally.
    tokio::spawn(async move {
        let _lease = fluxpeer_relay_server::auth::Lease(identity);
        loop {
            tokio::select! {
                out = out_rx.recv() => match out {
                    Some((dst, payload)) => {
                        if sender.send(RelayFrame::SendPacket { dst, payload }.encode()).await.is_err() {
                            return;
                        }
                    }
                    None => return, // app dropped the sender → shut down
                },
                r = receiver.recv() => match r {
                    Err(_) => return,
                    Ok(bytes) => {
                        // Only RecvPacket carries data; other frames (Pong, etc.) or a
                        // decode error are ignored.
                        if let Ok((RelayFrame::RecvPacket { src, payload }, _)) = RelayFrame::decode(&bytes)
                            && in_tx.send((src, payload)).await.is_err()
                        {
                            return;
                        }
                    }
                },
            }
        }
    });
    Ok((in_rx, out_tx))
}

fn validate_server_info(bytes: &[u8]) -> std::io::Result<()> {
    match RelayFrame::decode(bytes) {
        Ok((RelayFrame::ServerInfo { protocol_version: RELAY_PROTOCOL_VERSION }, n)) if n == bytes.len() => Ok(()),
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected relay ServerInfo version 2")),
    }
}

/// One relay the node can connect to (from the directory or hand-written cfg).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayTarget {
    pub(crate) addr: SocketAddr,
    pub(crate) anytls: bool,
    /// Aggregate N TCP links into a health-weighted bond instead of one plain TCP.
    pub(crate) bond: bool,
    /// Links a bonded transport (anytls or tcp-bond) aggregates; None = default (3).
    pub(crate) bond_links: Option<usize>,
    pub(crate) node_id: String,
    pub(crate) public_key: Option<[u8; 32]>,
}

/// Dial one relay (AnyTLS/443 or plain TCP) and run the framing handshake, with a
/// timeout so a black-holed target can't stall failover.
pub(crate) async fn dial_relay(t: &RelayTarget, own_priv: &StaticSecret) -> std::io::Result<(RelayIn, RelaySender)> {
    // The bond paths (anytls/443 and tcp-bond) establish N links + an N-way join
    // handshake, so they need a longer ceiling than a single plain-TCP connect
    // (default 10s join timeout). Keep the plain path snappy so a black-holed
    // target fails over fast.
    let dial_timeout = if t.anytls || t.bond {
        Duration::from_secs(12)
    } else {
        Duration::from_secs(5)
    };
    let relay_key = t.public_key.ok_or_else(|| fp_transport::link::denied("relay protocol v2 requires a pinned public_key"))?;
    let auth = std::sync::Arc::new(ClientAuth::new(own_priv.clone(), relay_key));
    let own_pub = PublicKey::from(own_priv).to_bytes();
    let connect = async {
        if t.anytls {
            // AnyTLS/443 over the bonded connector: N TLS yamux links aggregated
            // into one message-oriented transport. The node_id seeds the shared
            // AnyTLS password (process-global, read by `AnytlsConnector::connect`).
            let mut acfg = fp_transport_anytls::AnytlsConfig::with_node_id(&t.node_id);
            if let Some(n) = t.bond_links {
                acfg.bond_connections = n;
            }
            fp_transport_anytls::set_anytls_config(acfg);
            let (sender, receiver) =
                fp_transport_anytls::AnytlsConnector::connect_authenticated(fp_transport::Config {
                    endpoint: t.addr.ip(),
                    port: t.addr.port(),
                    timeout: Duration::from_secs(10),
                    tls: None,
                }, Some(auth.clone()))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            connect_relay_bonded(sender, receiver, own_pub).await
        } else if t.bond {
            if let Some(n) = t.bond_links {
                fp_transport_tcp_bond::set_tcp_bond_config(fp_transport_tcp_bond::TcpBondConfig {
                    bond_connections: n,
                    ..Default::default()
                });
            }
            let (sender, receiver) =
                fp_transport_tcp_bond::TcpBondConnector::connect_authenticated(fp_transport::Config {
                    endpoint: t.addr.ip(),
                    port: t.addr.port(),
                    timeout: Duration::from_secs(10),
                    tls: None,
                }, Some(auth.clone()))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            connect_relay_bonded(sender, receiver, own_pub).await
        } else {
            // Protect-before-connect (mobile): the relay egress socket must leave
            // on the real interface, not loop into the VPN tun. No-op off mobile.
            let s = fp_transport::connect_tcp(t.addr).await?;
            s.set_nodelay(true).ok();
            connect_relay(s, &auth).await
        }
    };
    tokio::time::timeout(dial_timeout, connect)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "relay dial timeout"))?
}

/// Keep exactly one relay connection alive, failing over across `targets` when a
/// dial fails or an active connection drops. Bridges the per-connection channels
/// to the app's stable `app_in`/`app_out` so the data-plane loop is oblivious to
/// reconnects. Returns only when the app shuts down (its channels close).
pub(crate) async fn relay_supervisor(
    mut targets: tokio::sync::watch::Receiver<Vec<RelayTarget>>,
    own_priv: StaticSecret,
    mut app_out_rx: mpsc::Receiver<([u8; 32], Vec<u8>)>,
    app_in_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
) {
    let mut idx = 0usize;
    loop {
        let target = {
            let snapshot = targets.borrow_and_update();
            snapshot.get(idx.checked_rem(snapshot.len()).unwrap_or(0)).cloned()
        };
        let Some(t) = target else {
            tokio::select! {
                changed = targets.changed() => if changed.is_err() { return; },
                _ = app_in_tx.closed() => return,
                out = app_out_rx.recv() => if out.is_none() { return; },
            }
            continue;
        };
        idx = idx.wrapping_add(1);
        let (mut conn_in, conn_out) = match dial_relay(&t, &own_priv).await {
            Ok(c) => {
                let transport = if t.anytls {
                    "anytls/443"
                } else if t.bond {
                    "tcp-bond"
                } else {
                    "tcp"
                };
                tracing::info!(addr = %t.addr, transport, "relay connected");
                c
            }
            Err(e) => {
                tracing::warn!(addr = %t.addr, error = %e, "relay dial failed; trying next");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        let mut app_gone = false;
        loop {
            tokio::select! {
                out = app_out_rx.recv() => match out {
                    Some(msg) => {
                        if conn_out.send(msg).await.is_err() {
                            break; // writer task died → connection dead
                        }
                    }
                    None => {
                        app_gone = true;
                        break;
                    }
                },
                inb = conn_in.recv() => match inb {
                    Some(msg) => {
                        if app_in_tx.send(msg).await.is_err() {
                            app_gone = true;
                            break;
                        }
                    }
                    None => {
                        tracing::warn!(addr = %t.addr, "relay disconnected; failing over");
                        break;
                    }
                },
            }
        }
        if app_gone {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await; // backoff before failover dial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn initially_empty_supervisor_connects_after_directory_publication() {
        // A loopback protocol fixture, without a live node or relay daemon.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _session = fluxpeer_relay_server::auth::ServerAuth::new(StaticSecret::from([123; 32])).plain(&mut stream).await.unwrap();
            let mut request = [0; 41];
            stream.read_exact(&mut request).await.unwrap();
            assert!(matches!(RelayFrame::decode(&request).unwrap().0, RelayFrame::ClientInfo { .. }));
            stream.write_all(&RelayFrame::ServerInfo { protocol_version: RELAY_PROTOCOL_VERSION }.encode()).await.unwrap();
            stream.write_all(&RelayFrame::RecvPacket { src: [3; 32], payload: b"recovered".to_vec() }.encode()).await.unwrap();
            std::future::pending::<()>().await;
        });
        let (targets, updates) = tokio::sync::watch::channel(vec![]);
        let (app_out, outgoing) = mpsc::channel(8);
        let (incoming, mut app_in) = mpsc::channel(8);
        let supervisor = tokio::spawn(relay_supervisor(updates, StaticSecret::from([1; 32]), outgoing, incoming));
        tokio::task::yield_now().await;
        assert!(!supervisor.is_finished());
        targets.send_replace(vec![RelayTarget { addr, anytls: false, bond: false, bond_links: None, node_id: "edge".into(), public_key: Some(PublicKey::from(&StaticSecret::from([123; 32])).to_bytes()) }]);
        let received = tokio::time::timeout(Duration::from_secs(2), app_in.recv()).await.unwrap().unwrap();
        assert_eq!(received, ([3; 32], b"recovered".to_vec()));
        drop(app_out); drop(app_in);
        tokio::time::timeout(Duration::from_secs(2), supervisor).await.unwrap().unwrap();
        fixture.abort();
    }
    #[test]
    fn rejects_wrong_server_info_version_and_frame_kind() {
        assert!(validate_server_info(&RelayFrame::ServerInfo { protocol_version: 1 }.encode()).is_err());
        assert!(validate_server_info(&RelayFrame::Ping { data: [0; 8] }.encode()).is_err());
        assert!(validate_server_info(&RelayFrame::ServerInfo { protocol_version: 2 }.encode()).is_ok());
    }

}
