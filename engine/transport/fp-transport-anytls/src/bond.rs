//! Bond: aggregate N TLS connections into one logical transport channel.
//!
//! - Send: pick the healthiest connection, retry on failure.
//! - Recv: all connections push into a shared channel, first packet wins.
//! - Reconnect: dead connections are replaced in background.

use crate::config::AnytlsConfig;
use crate::conn::ManagedConnection;
use crate::health::ConnHealth;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, RwLock};
use tokio_util::compat::FuturesAsyncReadCompatExt;

/// Per-link send queue depth (frames); full → spray to the next link.
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
    /// Round-robin cursor for spraying frames across links.
    spray: AtomicUsize,
    recv_rx: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    recv_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    closed: AtomicBool,
    close_notify: Notify,
    /// Fired when any bond reader task exits unexpectedly. The background
    /// health-check loop awaits this to trigger immediate replenishment
    /// instead of waiting for the next interval tick. Added 2026-05-20 after
    /// audit found 30s tick missed 14s middlebox-reset window.
    reader_dead_notify: Arc<Notify>,
}

impl BondGroup {
    pub fn new(bond_id: [u8; 16]) -> Arc<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        Arc::new(Self {
            bond_id,
            links: RwLock::new(Vec::new()),
            spray: AtomicUsize::new(0),
            recv_rx: Mutex::new(rx),
            recv_tx: tx,
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
            reader_dead_notify: Arc::new(Notify::new()),
        })
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.close_notify.notify_waiters();
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Add a yamux stream from a bonded connection. Spawns a reader task.
    pub async fn add_stream(&self, conn_id: usize, health: Arc<ConnHealth>, stream: yamux::Stream) {
        if self.is_closed() {
            tracing::warn!(conn_id, "dropping stream on closed BondGroup");
            return;
        }
        let compat = stream.compat();
        let (reader, mut writer) = tokio::io::split(compat);

        // Send task: write a whole batch of pending frames, then ONE flush —
        // per-frame flush pins yamux throughput to a round-trip per packet.
        let (tx, mut srx) = tokio::sync::mpsc::channel::<Vec<u8>>(LINK_QUEUE);
        let health_w = health.clone();
        tokio::spawn(async move {
            'pump: while let Some(first) = srx.recv().await {
                let mut batch = first.len() as u64;
                if write_frame(&mut writer, &first).await.is_err() {
                    break;
                }
                while let Ok(more) = srx.try_recv() {
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
        });
        self.links.write().await.push(Link {
            health: health.clone(),
            tx,
        });

        // Spawn reader: pushes received packets into shared channel
        let tx = self.recv_tx.clone();
        let health_for_reader = health.clone();
        let reader_dead_notify = self.reader_dead_notify.clone();
        tokio::spawn(async move {
            let mut rdr = reader;
            loop {
                match read_length_prefixed(&mut rdr).await {
                    Ok(pkt) => {
                        if pkt.is_empty() {
                            continue;
                        }
                        health_for_reader.add_bytes(pkt.len() as u64);
                        health_for_reader.touch_activity();
                        if tx.send(pkt).await.is_err() {
                            break; // receiver dropped
                        }
                    }
                    Err(e) => {
                        tracing::warn!(conn_id, "Bond reader ended: {}", e);
                        health_for_reader.record_failure();
                        // Wake the health-check loop so it can replenish
                        // immediately, instead of waiting for the next tick.
                        reader_dead_notify.notify_one();
                        break;
                    }
                }
            }
        });

        tracing::info!(conn_id, "Stream added to bond group");
    }

    /// Send a packet through the best available connection.
    /// Retries on the next-best if the chosen one fails.
    pub async fn send(&self, mut pkt: Vec<u8>) -> Result<(), fp_transport::Error> {
        if self.is_closed() {
            return Err(fp_transport::Error::UnexpectedResult("bond group closed".into()));
        }
        let links = self.links.read().await;
        let n = links.len();
        if n == 0 {
            return Err(fp_transport::Error::UnexpectedResult("no bonded connections".into()));
        }
        // Spray: round-robin from a rotating cursor, skipping dead links and links
        // whose queue is full (try the next). All full/dead → drop (wg retransmits).
        let start = self.spray.fetch_add(1, Ordering::Relaxed) % n;
        for k in 0..n {
            let link = &links[(start + k) % n];
            if link.health.is_dead() {
                continue;
            }
            match link.tx.try_send(pkt) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(p)) | Err(TrySendError::Closed(p)) => pkt = p,
            }
        }
        Err(fp_transport::Error::UnexpectedResult(
            "all bonded links busy/failed".into(),
        ))
    }

    /// Receive the next packet from any bonded connection.
    pub async fn recv(&self) -> Result<Vec<u8>, fp_transport::Error> {
        if self.is_closed() {
            return Err(fp_transport::Error::UnexpectedResult("bond group closed".into()));
        }
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
}

// ── BondedSender / BondedReceiver implement TransportSender / TransportReceiver ──

pub struct BondedSender {
    pub group: Arc<BondGroup>,
}

#[async_trait::async_trait]
impl fp_transport::TransportSender for BondedSender {
    async fn send(&mut self, pkt: Vec<u8>) -> Result<(), fp_transport::Error> {
        self.group.send(pkt).await
    }
    async fn close(&mut self) {
        self.group.close();
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
        self.group.close();
    }
}

// ── Client-side: build a bond group with N connections ──

pub async fn build_client_bond(
    config: &AnytlsConfig,
    addr: SocketAddr,
    tls_connector: &Arc<tokio_rustls::TlsConnector>,
) -> Result<Arc<BondGroup>, fp_transport::Error> {
    let bond_id = crate::conn::generate_bond_id();
    let n = config.effective_bond_connections();
    let group = BondGroup::new(bond_id);

    // Establish N connections concurrently
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let cfg = config.clone();
        let a = addr;
        let tc = tls_connector.clone();
        let bid = bond_id;
        handles.push(tokio::spawn(async move {
            ManagedConnection::connect(i, a, &cfg, &tc, &bid).await
        }));
    }

    let mut conns: Vec<ManagedConnection> = Vec::with_capacity(n);
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(cws)) => {
                // Stream was already opened and SYN flushed inside connect()
                group.add_stream(cws.conn.id, cws.conn.health.clone(), cws.stream).await;
                conns.push(cws.conn);
            }
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

    // Background: health check + reconnect dead connections
    let group_for_bg = group.clone();
    let config_for_bg = config.clone();
    let tls_for_bg = tls_connector.clone();
    let mut next_id = conns.len();
    // Keep managed connections alive (their drivers need to stay running)
    let managed = Arc::new(RwLock::new(conns));
    let managed_for_bg = managed.clone();
    let group_for_bg_task = group.clone();

    let reader_dead_notify = group.reader_dead_notify.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config_for_bg.health_check_interval);
        loop {
            tokio::select! {
                _ = group_for_bg_task.close_notify.notified() => {
                    break;
                }
                _ = reader_dead_notify.notified() => {
                    // Bond reader died — replenish now rather than waiting
                    // for the next tick. See 2026-05-20 audit.
                    tracing::info!("Bond reader death → immediate replenishment");
                }
                _ = interval.tick() => {}
            }

            if group_for_bg_task.is_closed() {
                break;
            }

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
                match ManagedConnection::connect(next_id, addr, &config_for_bg, &tls_for_bg, &bid).await {
                    Ok(cws) => {
                        group_for_bg
                            .add_stream(cws.conn.id, cws.conn.health.clone(), cws.stream)
                            .await;
                        managed_for_bg.write().await.push(cws.conn);
                        next_id += 1;
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

// ── Length-prefixed framing helpers ──

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

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
