//! Relay transport: one connection multiplexed by pubkey, with failover.

use std::net::SocketAddr;
use std::time::Duration;

use fluxpeer_relay_server::proto::Frame as RelayFrame;
use fluxpeer_relay_server::server::RELAY_PROTOCOL_VERSION;
use fp_transport::{TransportReceiver, TransportSender};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Relay channels are keyed by peer pubkey so ONE relay connection multiplexes
/// every peer: inbound `(src, payload)`, outbound `(dst, payload)`.
pub(crate) type RelayIn = mpsc::Receiver<([u8; 32], Vec<u8>)>;
pub(crate) type RelayOut = mpsc::Sender<([u8; 32], Vec<u8>)>;

/// Drive the relay protocol over a byte stream (TCP or AnyTLS): handshake, then
/// spawn reader/writer tasks keyed by peer pubkey. Returns keyed channels.
pub(crate) async fn connect_relay<S>(stream: S, own_pub: [u8; 32]) -> std::io::Result<(RelayIn, RelayOut)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
    rd.read_exact(&mut vec![0u8; len]).await?;

    let (in_tx, in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    let (out_tx, mut out_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    // ONE task drives read + write + a 3s keepalive Ping. Unifying them means the
    // connection has a single lifetime: any of EOF, a write error, a failed
    // keepalive (dead relay, even when idle), or the app dropping `out_tx` ends the
    // task, drops `in_tx`, and closes `in_rx` — the supervisor's failover signal.
    tokio::spawn(async move {
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
) -> std::io::Result<(RelayIn, RelayOut)> {
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
    // First reply is ServerInfo — read and discard.
    receiver
        .recv()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let (in_tx, in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    let (out_tx, mut out_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
    // ONE task drives read + write. Any of: a recv/send error, or the app dropping
    // `out_tx`, ends the task, drops `in_tx`, and closes `in_rx` — the supervisor's
    // failover signal. The bond handles keepalive/reconnect internally.
    tokio::spawn(async move {
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

/// One relay the node can connect to (from the directory or hand-written cfg).
#[derive(Clone)]
pub(crate) struct RelayTarget {
    pub(crate) addr: SocketAddr,
    pub(crate) anytls: bool,
    /// Aggregate N TCP links into a health-weighted bond instead of one plain TCP.
    pub(crate) bond: bool,
    /// Links a bonded transport (anytls or tcp-bond) aggregates; None = default (3).
    pub(crate) bond_links: Option<usize>,
    pub(crate) node_id: String,
}

/// Dial one relay (AnyTLS/443 or plain TCP) and run the framing handshake, with a
/// timeout so a black-holed target can't stall failover.
pub(crate) async fn dial_relay(t: &RelayTarget, own_pub: [u8; 32]) -> std::io::Result<(RelayIn, RelayOut)> {
    // The bond paths (anytls/443 and tcp-bond) establish N links + an N-way join
    // handshake, so they need a longer ceiling than a single plain-TCP connect
    // (default 10s join timeout). Keep the plain path snappy so a black-holed
    // target fails over fast.
    let dial_timeout = if t.anytls || t.bond {
        Duration::from_secs(12)
    } else {
        Duration::from_secs(5)
    };
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
                <fp_transport_anytls::AnytlsConnector as fp_transport::Connector>::connect(fp_transport::Config {
                    endpoint: t.addr.ip(),
                    port: t.addr.port(),
                    timeout: Duration::from_secs(10),
                    tls: None,
                })
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
                <fp_transport_tcp_bond::TcpBondConnector as fp_transport::Connector>::connect(fp_transport::Config {
                    endpoint: t.addr.ip(),
                    port: t.addr.port(),
                    timeout: Duration::from_secs(10),
                    tls: None,
                })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            connect_relay_bonded(sender, receiver, own_pub).await
        } else {
            let s = TcpStream::connect(t.addr).await?;
            s.set_nodelay(true).ok();
            connect_relay(s, own_pub).await
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
    targets: Vec<RelayTarget>,
    own_pub: [u8; 32],
    mut app_out_rx: mpsc::Receiver<([u8; 32], Vec<u8>)>,
    app_in_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
) {
    let mut idx = 0usize;
    loop {
        let t = targets[idx % targets.len()].clone();
        idx += 1;
        let (mut conn_in, conn_out) = match dial_relay(&t, own_pub).await {
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
