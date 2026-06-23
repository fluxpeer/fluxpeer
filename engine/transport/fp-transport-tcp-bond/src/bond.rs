//! Bond: aggregate N TCP connections into one logical transport channel.
//!
//! - Send: round-robin SPRAY across healthy links so a single flow uses every
//! link, not just the best one. Each link has its own send task that COALESCES
//! (writes a whole batch of pending frames, then one `flush`) — per-packet flush
//! pins yamux throughput to a synchronous round-trip per frame. Frames may
//! arrive reordered across links; the carried wg datagrams tolerate that (replay
//! window), and each frame is length-prefixed so it's never split across links.
//! - Recv: all connections push into a shared channel, first packet wins.
//! - Reconnect: dead connections are replaced in background.

use crate::config::TcpBondConfig;
use crate::conn::ManagedConnection;
use crate::health::{BondHealthSummary, ConnHealth};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, RwLock};
use tokio_util::compat::FuturesAsyncReadCompatExt;

/// Per-link send queue depth (frames). Full → spray skips to the next link;
/// all full → drop (wg retransmits), preserving the drop-on-full philosophy
/// while N links multiply the buffer.
const LINK_QUEUE: usize = 1024;

/// One bonded link: its health + the queue feeding its dedicated send task.
struct Link {
    health: Arc<ConnHealth>,
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

/// A group of bonded connections that looks like one (Sender, Receiver) to the upper layer.
pub struct BondGroup {
    pub bond_id: [u8; 16],
    links: RwLock<Vec<Link>>,
    recv_rx: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    recv_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Round-robin cursor for spraying frames across links.
    spray: AtomicUsize,
}

impl BondGroup {
    pub fn new(bond_id: [u8; 16]) -> Arc<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        Arc::new(Self {
            bond_id,
            links: RwLock::new(Vec::new()),
            recv_rx: Mutex::new(rx),
            recv_tx: tx,
            spray: AtomicUsize::new(0),
        })
    }

    /// Add a yamux stream from a bonded connection. Spawns a per-link send task
    /// (coalescing writer) + a reader task.
    pub async fn add_stream(&self, conn_id: usize, health: Arc<ConnHealth>, stream: yamux::Stream) {
        let compat = stream.compat();
        let (reader, mut writer) = tokio::io::split(compat);

        // Prime the stream with a zero-length frame. yamux opens outbound streams
        // lazily (the SYN is not sent until the first write), so without this the
        // server's `accept` never sees a per-connection inbound stream for any link
        // the bond's send-path doesn't happen to pick — leaving those links unusable
        // and stalling the server handshake. A zero-length frame is a no-op on the
        // read side (both ends skip empty frames); flush it to push the SYN now.
        if write_frame(&mut writer, &[]).await.is_err() || writer.flush().await.is_err() {
            tracing::debug!(conn_id, "Bond stream prime failed");
        }

        // Send task: drain the queue, writing a whole batch before a single flush.
        // At line rate many frames coalesce into one flush (throughput); at low
        // rate one frame writes+flushes immediately (latency, e.g. keepalive/ping).
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(LINK_QUEUE);
        let health_w = health.clone();
        tokio::spawn(async move {
            'pump: while let Some(first) = rx.recv().await {
                let mut batch = first.len() as u64;
                if write_frame(&mut writer, &first).await.is_err() {
                    break;
                }
                while let Ok(more) = rx.try_recv() {
                    batch += more.len() as u64;
                    if write_frame(&mut writer, &more).await.is_err() {
                        break 'pump;
                    }
                }
                if writer.flush().await.is_err() {
                    break;
                }
                health_w.add_bytes(batch);
                health_w.touch_activity();
            }
            health_w.record_failure();
            tracing::debug!(conn_id, "Bond send task ended");
        });

        self.links.write().await.push(Link {
            health: health.clone(),
            tx,
        });

        // Reader: pushes received packets into the shared channel.
        let rtx = self.recv_tx.clone();
        let health_r = health.clone();
        tokio::spawn(async move {
            let mut rdr = reader;
            loop {
                match read_length_prefixed(&mut rdr).await {
                    Ok(pkt) => {
                        if pkt.is_empty() {
                            continue;
                        }
                        health_r.add_bytes(pkt.len() as u64);
                        health_r.touch_activity();
                        if rtx.send(pkt).await.is_err() {
                            break; // receiver dropped
                        }
                    }
                    Err(e) => {
                        tracing::debug!(conn_id, "Bond reader ended: {}", e);
                        health_r.record_failure();
                        break;
                    }
                }
            }
        });

        tracing::info!(conn_id, "Stream added to bond group");
    }

    /// Spray a packet across the bonded links: round-robin from a rotating cursor,
    /// skipping dead links and links whose queue is full (try the next). All
    /// full/dead → drop (wg retransmits). Spreads a single flow over every link.
    pub async fn send(&self, mut pkt: Vec<u8>) -> Result<(), fp_transport::Error> {
        let links = self.links.read().await;
        let n = links.len();
        if n == 0 {
            return Err(fp_transport::Error::UnexpectedResult("no bonded connections".into()));
        }
        let start = self.spray.fetch_add(1, Ordering::Relaxed) % n;
        for k in 0..n {
            let link = &links[(start + k) % n];
            if link.health.is_dead() {
                continue;
            }
            match link.tx.try_send(pkt) {
                Ok(()) => return Ok(()),
                // This link is backed up or its send task is gone — try the next,
                // reclaiming the packet (try_send hands it back on failure).
                Err(TrySendError::Full(p)) | Err(TrySendError::Closed(p)) => pkt = p,
            }
        }
        Err(fp_transport::Error::UnexpectedResult(
            "all bonded links busy/failed".into(),
        ))
    }

    /// Receive the next packet from any bonded connection.
    pub async fn recv(&self) -> Result<Vec<u8>, fp_transport::Error> {
        self.recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(fp_transport::Error::UnexpectedResult("all bond readers closed".into()))
    }

    /// Number of alive (weight > 0) connections.
    pub async fn alive_count(&self) -> usize {
        let links = self.links.read().await;
        links.iter().filter(|l| !l.health.is_dead()).count()
    }

    /// Aggregate health summary across all bonded connections.
    #[allow(dead_code)]
    pub async fn health_summary(&self) -> BondHealthSummary {
        let links = self.links.read().await;
        let mut alive_count = 0usize;
        let mut dead_count = 0usize;
        let mut rtt_sum = 0u64;
        let mut total_bytes = 0u64;

        for l in links.iter() {
            if l.health.is_dead() {
                dead_count += 1;
            } else {
                alive_count += 1;
                rtt_sum = rtt_sum.saturating_add(l.health.rtt_ms());
            }
            total_bytes = total_bytes.saturating_add(l.health.total_bytes());
        }

        let avg_rtt_ms = if alive_count > 0 {
            rtt_sum / alive_count as u64
        } else {
            0
        };

        BondHealthSummary {
            alive_count,
            dead_count,
            avg_rtt_ms,
            total_bytes,
        }
    }
}

// -- BondedSender / BondedReceiver implement TransportSender / TransportReceiver --

pub struct BondedSender {
    pub group: Arc<BondGroup>,
}

#[async_trait::async_trait]
impl fp_transport::TransportSender for BondedSender {
    async fn send(&mut self, pkt: Vec<u8>) -> Result<(), fp_transport::Error> {
        self.group.send(pkt).await
    }
    async fn close(&mut self) {
        // Writers will be closed when BondGroup is dropped
    }
}

pub struct BondedReceiver {
    pub group: Arc<BondGroup>,
}

#[async_trait::async_trait]
impl fp_transport::TransportReceiver for BondedReceiver {
    async fn recv(&mut self) -> Result<Vec<u8>, fp_transport::Error> {
        self.group.recv().await
    }
    async fn close(&mut self) {
        // Readers will stop when BondGroup is dropped
    }
}

// -- Client-side: build a bond group with N connections --

pub async fn build_client_bond(
    config: &TcpBondConfig,
    addr: SocketAddr,
) -> Result<Arc<BondGroup>, fp_transport::Error> {
    let bond_id = crate::conn::generate_bond_id();
    let n = config.effective_bond_connections();
    let group = BondGroup::new(bond_id);

    // Establish N connections concurrently
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let cfg = config.clone();
        let a = addr;
        let bid = bond_id;
        handles.push(tokio::spawn(async move {
            ManagedConnection::connect(i, a, &cfg, &bid).await
        }));
    }

    let mut conns: Vec<ManagedConnection> = Vec::with_capacity(n);
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(conn)) => conns.push(conn),
            Ok(Err(e)) => {
                tracing::warn!(i, "Bond connection {} failed: {}", i, e);
            }
            Err(e) => {
                tracing::warn!(i, "Bond connection {} panicked: {}", i, e);
            }
        }
    }

    if conns.is_empty() {
        return Err(fp_transport::Error::UnexpectedResult(
            "all bond connections failed".into(),
        ));
    }

    tracing::info!(
        total = conns.len(),
        target = n,
        "Bond group established ({}/{})",
        conns.len(),
        n
    );

    // Open one yamux stream per connection, add to bond group
    for conn in &conns {
        match conn.open_stream().await {
            Ok(stream) => {
                group.add_stream(conn.id, conn.health.clone(), stream).await;
            }
            Err(e) => {
                tracing::warn!(conn_id = conn.id, "Failed to open stream: {}", e);
            }
        }
    }

    // Background: health check + reconnect dead connections
    let group_for_bg = group.clone();
    let config_for_bg = config.clone();
    let mut next_id = conns.len();
    // Keep managed connections alive (their drivers need to stay running)
    let managed = Arc::new(RwLock::new(conns));
    let managed_for_bg = managed.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config_for_bg.health_check_interval);
        loop {
            interval.tick().await;

            // Ping all managed connections
            {
                let conns = managed_for_bg.read().await;
                for conn in conns.iter() {
                    let _ = conn.ping(config_for_bg.health_check_timeout).await;
                }
            }

            // Log stale connections (dead + no activity for 90s)
            {
                let conns = managed_for_bg.read().await;
                for conn in conns.iter() {
                    if conn.health.is_stale(90) {
                        tracing::info!(
                            conn_id = conn.id,
                            last_activity = conn.health.last_activity_secs(),
                            "Stale connection detected (dead + inactive >90s)"
                        );
                    }
                }
            }

            // Reconnect if below target
            let alive = group_for_bg.alive_count().await;
            let target = config_for_bg.effective_bond_connections();
            if alive < target {
                tracing::info!(alive, target, "Replenishing bond connections");
                let bid = group_for_bg.bond_id;
                match ManagedConnection::connect(next_id, addr, &config_for_bg, &bid).await {
                    Ok(conn) => {
                        if let Ok(stream) = conn.open_stream().await {
                            group_for_bg.add_stream(conn.id, conn.health.clone(), stream).await;
                            managed_for_bg.write().await.push(conn);
                            next_id += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Reconnect failed: {}", e);
                    }
                }
            }
        }
    });

    Ok(group)
}

// -- Length-prefixed framing helpers --

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

/// Write one length-prefixed frame WITHOUT flushing — the caller flushes once per
/// batch (see the send task). Per-frame flush would pin throughput to a yamux
/// round-trip per packet.
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> Result<(), std::io::Error> {
    if data.len() > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame size {} exceeds maximum {}", data.len(), MAX_FRAME_SIZE),
        ));
    }
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await
}

async fn read_length_prefixed<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame size {} exceeds maximum {}", len, MAX_FRAME_SIZE),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
