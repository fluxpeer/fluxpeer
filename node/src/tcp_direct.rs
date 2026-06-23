//! TCP-direct transport (the middle rung), multi-peer.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// TCP-direct channel facts the main loop needs: inbound `(peer pubkey, wg)` and
/// connection up/down `(peer pubkey, Some(out) | None)`.
pub(crate) type TcpIn = mpsc::Receiver<([u8; 32], Vec<u8>)>;
// Connection up/down carries a per-connection generation so a dropped *old*
// connection's "down" can't clobber a freshly-redialed one's channel.
pub(crate) type TcpConn = mpsc::Receiver<([u8; 32], u64, Option<mpsc::Sender<Vec<u8>>>)>;
pub(crate) type TcpConnTx = mpsc::Sender<([u8; 32], u64, Option<mpsc::Sender<Vec<u8>>>)>;

/// Length-frame ([u32 BE len][wg]) a wg byte stream over a direct peer-to-peer TCP
/// connection. ONE task drives read + write (mirrors `connect_relay`): inbound
/// frames are tagged with the connection's peer `pk` and pushed to `in_tx`;
/// `out_rx` frames are written out. Returns when the connection drops or `out_rx`
/// closes — the signal to clear the peer's `tcp_out`.
pub(crate) async fn frame_pump<S>(
    stream: S,
    pk: [u8; 32],
    in_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // Bidirectional transport liveness: both ends send a zero-length keepalive
    // frame every 3s. If NOTHING arrives for ~3 ticks the connection is dead and
    // we return — clearing the peer's `tcp_out` so the ladder falls back to the
    // relay. This is essential because a NAT can black-hole one direction (writes
    // just pile up in the send queue, never erroring), so a one-way write check or
    // TCP read-EOF would never notice. An empty wg frame decodes to nothing and is
    // ignored on receipt.
    let mut ka = tokio::time::interval(Duration::from_secs(3));
    ka.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut idle_ticks = 0u32;
    loop {
        tokio::select! {
            _ = ka.tick() => {
                idle_ticks += 1;
                if idle_ticks >= 3 {
                    return; // ~9s with no inbound — connection black-holed
                }
                if wr.write_all(&0u32.to_be_bytes()).await.is_err() {
                    return;
                }
            }
            out = out_rx.recv() => match out {
                Some(pkt) => {
                    let mut frame = (pkt.len() as u32).to_be_bytes().to_vec();
                    frame.extend_from_slice(&pkt);
                    if wr.write_all(&frame).await.is_err() {
                        return;
                    }
                }
                None => return,
            },
            r = rd.read(&mut tmp) => match r {
                Ok(0) | Err(_) => return,
                Ok(k) => {
                    idle_ticks = 0; // inbound bytes → connection is alive
                    buf.extend_from_slice(&tmp[..k]);
                    // Drain all complete [len][wg] frames.
                    loop {
                        if buf.len() < 4 {
                            break;
                        }
                        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                        if len > 65535 {
                            return; // framing desync / hostile length
                        }
                        if buf.len() < 4 + len {
                            break;
                        }
                        let wg = buf[4..4 + len].to_vec();
                        buf.drain(..4 + len);
                        if in_tx.send((pk, wg)).await.is_err() {
                            return;
                        }
                    }
                }
            },
        }
    }
}

/// Manage TCP-direct connections for every peer: the lexicographically-smaller
/// key dials `peer:listen_port` (redialing on drop); the larger one accepts. Each
/// side opens with a 32-byte pubkey so the other can attribute the connection.
/// Established/dropped connections are reported on `conn_tx` so the main loop sets
/// or clears `peer.tcp_out`; inbound wg flows to `in_tx`.
pub(crate) async fn tcp_direct_manager(
    listen_port: u16,
    own_pub: [u8; 32],
    targets: Vec<([u8; 32], Vec<SocketAddr>)>, // peers WE dial (we're the initiator)
    in_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
    conn_tx: TcpConnTx,
) {
    let gctr = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
    // Accept loop: a peer dialed us; read its pubkey, then pump.
    if let Ok(listener) = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, listen_port))).await {
        let (in_tx, conn_tx, gctr) = (in_tx.clone(), conn_tx.clone(), gctr.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let (in_tx, conn_tx, gctr) = (in_tx.clone(), conn_tx.clone(), gctr.clone());
                tokio::spawn(async move {
                    let mut pk = [0u8; 32];
                    if stream.read_exact(&mut pk).await.is_err() {
                        return;
                    }
                    stream.set_nodelay(true).ok();
                    let g = gctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(512);
                    if conn_tx.send((pk, g, Some(out_tx))).await.is_err() {
                        return;
                    }
                    tracing::info!(peer = %hex::encode(&pk[..4]), "tcp-direct accepted");
                    frame_pump(stream, pk, in_tx, out_rx).await;
                    let _ = conn_tx.send((pk, g, None)).await;
                });
            }
        });
    } else {
        tracing::warn!(port = listen_port, "tcp-direct: bind failed; accept disabled");
    }

    // Dial loop per initiator peer: keep one connection up, redial on drop.
    for (pk, cands) in targets {
        let (in_tx, conn_tx, gctr) = (in_tx.clone(), conn_tx.clone(), gctr.clone());
        tokio::spawn(async move {
            loop {
                let mut connected = false;
                for cand in &cands {
                    let dial = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(cand)).await;
                    let Ok(Ok(mut stream)) = dial else { continue };
                    if stream.write_all(&own_pub).await.is_err() {
                        continue;
                    }
                    stream.set_nodelay(true).ok();
                    let g = gctr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(512);
                    if conn_tx.send((pk, g, Some(out_tx))).await.is_err() {
                        return;
                    }
                    tracing::info!(peer = %hex::encode(&pk[..4]), addr = %cand, "tcp-direct dialed");
                    connected = true;
                    frame_pump(stream, pk, in_tx.clone(), out_rx).await;
                    let _ = conn_tx.send((pk, g, None)).await;
                    break;
                }
                // Backoff before the next (re)dial sweep.
                tokio::time::sleep(Duration::from_secs(if connected { 2 } else { 5 })).await;
            }
        });
    }
}
