//! Per-shard data-plane worker (multicore data plane).
//!
//! Each worker owns a partition of peers — their `RawCryptor`s (which are
//! `Send + Sync`) are driven exclusively here, so no cryptor is touched from two
//! threads. `N = available_parallelism()-1` workers run as `tokio::spawn` actors
//! the multi-thread runtime spreads across cores, restoring the previous server
//! dispatcher's multicore data plane.
//!
//! Central readers (UDP/TUN/relay/TCP) route each packet to the OWNING worker via
//! the `route_*` helpers below, then fan it in as a [`WorkerMsg`]; a single writer
//! task drains every worker's decrypted output to the one TUN fd.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use fp_crypto::x25519::{PublicKey, StaticSecret};
use fp_disco::Disco;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::peer::{Peer, accept_init, handle_wg, send_to_peer};
use crate::relay::RelayOut;
use crate::status::{self, PeerStat, StatusRegistry};
use crate::util::{
    DISCO_MAGIC, LIVENESS_DEAD_SECS, REKEY_AFTER_SECS, T_DATA, T_HANDSHAKE_INIT, T_HANDSHAKE_RESP, disco_dgram,
    ip_in_cidr, le_u32,
};

/// Shared `wg session index → owning worker id`, written by whichever worker
/// assigned the index and read by the UDP reader to route inbound RESP/DATA to
/// that worker. Rare writes (new session/rekey), hot reads → RwLock fits.
pub(crate) type IndexOwner = Arc<RwLock<HashMap<u32, usize>>>;

/// A worker's index table: a LOCAL `index → peer pubkey` map (its shard only, for
/// peer lookup) that also publishes `index → wid` into the shared [`IndexOwner`]
/// on every insert, so the reader can route to this worker.
pub(crate) struct IndexTable {
    local: HashMap<u32, [u8; 32]>,
    owner: IndexOwner,
    wid: usize,
}

impl IndexTable {
    pub(crate) fn new(local: HashMap<u32, [u8; 32]>, owner: IndexOwner, wid: usize) -> Self {
        Self { local, owner, wid }
    }
    pub(crate) fn insert(&mut self, idx: u32, pk: [u8; 32]) {
        self.local.insert(idx, pk);
        self.owner.write().insert(idx, self.wid);
    }
    pub(crate) fn get(&self, idx: u32) -> Option<[u8; 32]> {
        self.local.get(&idx).copied()
    }
    /// Drop every index this worker assigned to `pk` (local + the shared owner map),
    /// so a revoked peer's RESP/DATA no longer route anywhere (REVOKE-1).
    pub(crate) fn remove_peer(&mut self, pk: [u8; 32]) {
        let idxs: Vec<u32> = self
            .local
            .iter()
            .filter(|(_, v)| **v == pk)
            .map(|(k, _)| *k)
            .collect();
        if idxs.is_empty() {
            return;
        }
        let mut owner = self.owner.write();
        for idx in idxs {
            self.local.remove(&idx);
            owner.remove(&idx);
        }
    }
}

/// A unit of work fanned into a worker by the central reader tasks.
pub(crate) enum WorkerMsg {
    /// 1 Hz control tick: liveness / keepalive / relay fallback / proactive rekey.
    Tick,
    /// A datagram off the shared UDP socket (disco OR wg) for a peer this worker owns.
    UdpIn { from: SocketAddr, bytes: Vec<u8> },
    /// A wg frame off the relay (carries the peer pubkey, source-independent).
    RelayIn { src: [u8; 32], bytes: Vec<u8> },
    /// A wg frame off this peer's TCP-direct connection.
    TcpIn { src: [u8; 32], bytes: Vec<u8> },
    /// A TCP-direct connection to `pk` came up (`Some`) or dropped (`None`).
    TcpConn {
        pk: [u8; 32],
        conn_gen: u64,
        out: Option<mpsc::Sender<Vec<u8>>>,
    },
    /// An egress IP packet read off the TUN, already resolved to its owning peer.
    TunEgress { pk: [u8; 32], pkt: Vec<u8> },
    /// Reconcile (REVOKE-1): a peer JOINED the network — build its session and start
    /// handshaking (initiator side sends the first init). Idempotent.
    AddPeer {
        pubkey: [u8; 32],
        candidates: Vec<SocketAddr>,
        allowed_ips: Vec<String>,
        initiator: bool,
    },
    /// Reconcile (REVOKE-1): a peer was REVOKED/removed — drop its session so it can
    /// no longer send (we stop keepalives/data) or receive (no session → decrypt
    /// fails; a fresh init from it is ignored since `accept_init` needs a known peer).
    RemovePeer([u8; 32]),
    /// Reconcile: a peer re-reported a DIFFERENT endpoint set (it roamed/restarted).
    /// Update its disco candidates IN PLACE and re-open the hole — but KEEP the live
    /// wg session + receiver index. Tearing the session down here (the old
    /// remove+add) discarded our index while the peer kept sending it, so its DATA
    /// routed to nowhere → silent → relay flap (the multi-peer endpoint-churn bug).
    /// A genuinely restarted peer re-initiates itself (handled by `accept_init`).
    UpdateCandidates {
        pubkey: [u8; 32],
        candidates: Vec<SocketAddr>,
    },
}

/// Route an egress TUN packet to `(owning peer pubkey, worker id)` by destination
/// overlay IP. `allowed` is `(allowed_ips, pubkey, wid)` per peer.
pub(crate) fn route_tun(pkt: &[u8], allowed: &[(Vec<String>, [u8; 32], usize)]) -> Option<([u8; 32], usize)> {
    let Some(IpAddr::V4(dst)) = fp_crypto::dst_address(pkt) else {
        return None;
    };
    allowed
        .iter()
        .find(|(ips, _, _)| ips.iter().any(|c| ip_in_cidr(dst, c)))
        .map(|(_, pk, wid)| (*pk, *wid))
}

/// Route an inbound UDP datagram to the owning worker: disco by sender pubkey /
/// candidate, wg INIT by peeking its static pubkey, wg RESP/DATA by receiver index.
#[allow(clippy::too_many_arguments)]
pub(crate) fn route_udp(
    bytes: &[u8],
    from: SocketAddr,
    peer_to_wid: &HashMap<[u8; 32], usize>,
    cand_to_wid: &HashMap<SocketAddr, usize>,
    index_owner: &IndexOwner,
    own_priv: &StaticSecret,
    own_pub: &PublicKey,
) -> Option<usize> {
    if let Some(body) = bytes.strip_prefix(DISCO_MAGIC) {
        return match Disco::decode(body) {
            Ok((Disco::Ping { sender, .. }, _)) => peer_to_wid.get(&sender).copied(),
            // A Pong from a known candidate routes; a roaming Pong is dropped —
            // authenticated wg DATA (`set_path`) is the authority on roaming.
            Ok((Disco::Pong { .. }, _)) => cand_to_wid.get(&from).copied(),
            _ => None,
        };
    }
    if bytes.first().copied().unwrap_or(0) == T_HANDSHAKE_INIT {
        fp_crypto_noise::peek_init_pubkey(own_priv, own_pub, bytes).and_then(|pk| peer_to_wid.get(&pk).copied())
    } else {
        let idx = if bytes.first() == Some(&T_HANDSHAKE_RESP) {
            le_u32(bytes, 8)
        } else {
            le_u32(bytes, 4)
        };
        idx.and_then(|i| index_owner.read().get(&i).copied())
    }
}

/// Route a relay/TCP-direct frame (which carries `src` pubkey) to the owning
/// worker: an INIT by peeking its static pubkey, else by `src`.
pub(crate) fn route_framed(
    bytes: &[u8],
    src: &[u8; 32],
    peer_to_wid: &HashMap<[u8; 32], usize>,
    own_priv: &StaticSecret,
    own_pub: &PublicKey,
) -> Option<usize> {
    if bytes.first().copied().unwrap_or(0) == T_HANDSHAKE_INIT {
        fp_crypto_noise::peek_init_pubkey(own_priv, own_pub, bytes).and_then(|pk| peer_to_wid.get(&pk).copied())
    } else {
        peer_to_wid.get(src).copied()
    }
}

/// One worker's owned data-plane state (a partition of peers + their cryptors).
pub(crate) struct WorkerState {
    pub(crate) peers: Vec<Peer>,
    pub(crate) index_map: IndexTable,
    pub(crate) udp: Arc<UdpSocket>,
    pub(crate) relay_out: Option<RelayOut>,
    pub(crate) own_priv: StaticSecret,
    pub(crate) own_pub: PublicKey,
    pub(crate) force_relay: bool,
    pub(crate) ping: Vec<u8>,
    /// Decrypted IP packets out to the single TUN-writer task.
    pub(crate) tun_out: mpsc::Sender<Vec<u8>>,
    /// Shared live per-peer status/counters (this worker writes its shard's peers).
    pub(crate) status: StatusRegistry,
}

/// Emit a gapless rekey init on `peer` (the initiator side keeps the live session
/// encrypting until the response installs the new one) and record its index so the
/// peer's response routes back. Shared by the silent→relay fallback and the
/// proactive session-aging paths. Returns whether an init was actually sent.
/// Send a keepalive (encrypted empty data) down the peer's current path. A
/// relay-pinned peer ALSO fires it directly + a disco ping to re-open the hole and
/// test whether the direct path recovered (both ends do this, so a healed path
/// delivers each other's direct keepalive). Free fn so the tick loop stays flat.
async fn keepalive_send(
    udp: &UdpSocket,
    ping: &[u8],
    force_relay: bool,
    relay_out: &Option<RelayOut>,
    peer: &Peer,
    ka: &[u8],
) {
    send_to_peer(udp, peer, force_relay, relay_out, ka).await;
    if peer.relay_pinned && !force_relay {
        if let Some(addr) = peer.direct_addr {
            let _ = udp.send_to(ka, addr).await;
            let _ = udp.send_to(ping, addr).await;
        }
        for c in &peer.candidates {
            let _ = udp.send_to(ping, *c).await;
        }
    }
}

async fn emit_rekey(
    peer: &mut Peer,
    udp: &UdpSocket,
    force_relay: bool,
    relay_out: &Option<RelayOut>,
    index_map: &mut IndexTable,
) -> bool {
    let mut rbuf = [0u8; 256];
    let init = match peer.raw.rekey_init(&mut rbuf) {
        Ok(i) => i.to_vec(),
        Err(e) => {
            tracing::debug!(error = ?e, "rekey_init");
            return false;
        }
    };
    if let Some(idx) = le_u32(&init, 4) {
        index_map.insert(idx, peer.pubkey);
    }
    send_to_peer(udp, peer, force_relay, relay_out, &init).await;
    true
}

impl WorkerState {
    /// Drive this worker until its mailbox closes. One message at a time, exactly
    /// like the old single `select!` arm — preserves all liveness/rekey timing.
    pub(crate) async fn run(mut self, mut rx: mpsc::Receiver<WorkerMsg>) {
        let mut dbuf = [0u8; 2048];
        let mut ebuf = [0u8; 2048];
        let mut gso = crate::gso::GsoBatch::new();
        while let Some(msg) = rx.recv().await {
            self.handle(msg, &mut dbuf, &mut ebuf, &mut gso).await;
            // Drain the rest of the burst so consecutive TUN-egress packets to one
            // peer coalesce into a single GSO sendmsg (the udp-direct throughput win).
            while let Ok(more) = rx.try_recv() {
                self.handle(more, &mut dbuf, &mut ebuf, &mut gso).await;
            }
            gso.flush(&self.udp).await;
        }
    }

    async fn handle(&mut self, msg: WorkerMsg, dbuf: &mut [u8], ebuf: &mut [u8], gso: &mut crate::gso::GsoBatch) {
        match msg {
            WorkerMsg::TunEgress { pk, pkt } => self.on_tun_egress(pk, &pkt, ebuf, gso).await,
            WorkerMsg::TcpConn { pk, conn_gen, out } => self.on_tcp_conn(pk, conn_gen, out),
            WorkerMsg::AddPeer {
                pubkey,
                candidates,
                allowed_ips,
                initiator,
            } => {
                gso.flush(&self.udp).await;
                self.on_add_peer(pubkey, candidates, allowed_ips, initiator).await;
            }
            WorkerMsg::RemovePeer(pk) => self.on_remove_peer(pk),
            WorkerMsg::UpdateCandidates { pubkey, candidates } => {
                gso.flush(&self.udp).await;
                self.on_update_candidates(pubkey, candidates).await;
            }
            // Arms that may themselves send (handshake resp / keepalive) flush the
            // pending egress batch first so wire order stays sane.
            WorkerMsg::Tick => {
                gso.flush(&self.udp).await;
                self.on_tick(ebuf).await;
            }
            WorkerMsg::UdpIn { from, bytes } => {
                gso.flush(&self.udp).await;
                self.on_udp_in(from, &bytes, dbuf).await;
            }
            WorkerMsg::RelayIn { src, bytes } => {
                gso.flush(&self.udp).await;
                self.on_relay_in(src, &bytes, dbuf).await;
            }
            WorkerMsg::TcpIn { src, bytes } => {
                gso.flush(&self.udp).await;
                self.on_tcp_in(src, &bytes, dbuf).await;
            }
        }
    }

    async fn on_tick(&mut self, ebuf: &mut [u8]) {
        let now = Instant::now();
        for peer in self.peers.iter_mut() {
            // Publish a status snapshot for the local socket / `fluxpeer show`:
            // current transport rung (mirrors send_to_peer), rtt, endpoint.
            let tp = if !peer.handshaked {
                status::T_NONE
            } else if !self.force_relay && !peer.prefer_relay && peer.direct_addr.is_some() {
                status::T_UDP_DIRECT
            } else if !self.force_relay && peer.tcp_out.is_some() {
                status::T_TCP_DIRECT
            } else if self.relay_out.is_some() {
                status::T_RELAY
            } else if peer.direct_addr.is_some() {
                status::T_UDP_DIRECT
            } else {
                status::T_NONE
            };
            peer.stat.transport.store(tp, Ordering::Relaxed);
            peer.stat
                .rtt_us
                .store(peer.rtt.map(|r| r.as_micros() as u64).unwrap_or(0), Ordering::Relaxed);
            *peer.stat.endpoint.lock() = peer.direct_addr;

            if !self.force_relay && !peer.disco_validated {
                for c in &peer.candidates {
                    let _ = self.udp.send_to(&self.ping, *c).await;
                }
            }
            if !peer.handshaked {
                peer.retries += 1;
                // Give UDP-direct/disco a fair chance before relay fallback —
                // 6 ticks (vs 3) tolerates real cross-continent RTT + staggered
                // node startup, so a reachable WAN path isn't abandoned early.
                if !self.force_relay
                    && !peer.disco_validated
                    && !peer.prefer_relay
                    && self.relay_out.is_some()
                    && peer.retries >= 6
                {
                    peer.prefer_relay = true;
                    tracing::warn!("no direct path; falling back to relay");
                }
                if let Some(init) = peer.init_packet.clone() {
                    send_to_peer(&self.udp, peer, self.force_relay, &self.relay_out, &init).await;
                    peer.init_sent_at = Some(now); // measure RTT from the latest send
                }
                continue;
            }
            // Handshaked. Send a persistent keepalive (encrypted empty data) down
            // the current path — it keeps NAT mappings warm and, being AEAD-
            // authenticated, is the only honest liveness signal: disco Ping/Pong
            // can succeed while the *data* session is crossed/dead.
            if let Ok(out) = peer.raw.on_send(&[], ebuf) {
                if out.first() == Some(&T_DATA) {
                    let ka = out.to_vec();
                    peer.stat.add_tx(ka.len());
                    keepalive_send(&self.udp, &self.ping, self.force_relay, &self.relay_out, peer, &ka).await;
                } else if out.first() == Some(&T_HANDSHAKE_INIT)
                    && self.own_pub.as_bytes() < &peer.pubkey
                    && let Some(idx) = le_u32(out, 4)
                {
                    // The session aged out, so `on_send` emitted a rekey INIT instead
                    // of a keepalive — which already advanced OUR receiver index. Only
                    // the designated initiator (own_pub < peer, the same gate
                    // `emit_rekey`/`on_tun_egress` use so the two ends never
                    // cross-initiate) registers + sends it. Dropping it (the old
                    // behaviour) left the index advanced-but-unregistered, so the
                    // peer's next DATA carried a receiver index this node never put in
                    // `index_owner` → routed to nowhere → "direct path silent" →
                    // endless relay flap. The responder discards it and lets the
                    // initiator drive the rekey. This silently broke multi-peer meshes.
                    let init = out.to_vec();
                    self.index_map.insert(idx, peer.pubkey);
                    send_to_peer(&self.udp, peer, self.force_relay, &self.relay_out, &init).await;
                }
            }
            // If the DIRECT path goes silent (no decryptable packet *over UDP-direct*
            // for a while) the punch died — symmetric NAT remap, crossed sessions, etc.
            // Gate on `last_recv_direct`, NOT `last_recv`: the latter is refreshed by
            // RELAY traffic too, so a node that only hears a peer over the relay would
            // keep its direct path "alive" forever and keep replying into the dead
            // direct address — the peer reaches us via relay but we never reply via
            // relay, a one-way black hole (the mobile inbound-NAT failure). The
            // threshold is RTT-ADAPTIVE (>= 8×RTT, floor LIVENESS_DEAD_SECS) so a
            // high-latency WAN path isn't declared dead before its 1s keepalives arrive.
            let dead = peer.rtt.map_or(Duration::from_secs(LIVENESS_DEAD_SECS), |r| {
                (r * 8).max(Duration::from_secs(LIVENESS_DEAD_SECS))
            });
            let silent = peer.last_recv_direct.map(|t| now.duration_since(t) >= dead).unwrap_or(true);
            if silent && !peer.prefer_relay && !self.force_relay && self.relay_out.is_some() {
                // Move to relay but keep the LIVE session and rekey GAPLESSLY
                // (rekey_init, not a rebuild): the old session keeps decrypting
                // in-flight direct packets, so the peer doesn't desync and
                // re-trigger "silent" forever (the WAN thrash). Genuinely-dead
                // paths still converge to relay; the re-probe upgrades back.
                tracing::warn!("direct path silent; rekeying over relay");
                peer.prefer_relay = true;
                peer.relay_pinned = true;
                // Hysteresis: if we upgraded off relay only moments ago, this is a
                // flap — count it (capped) so the upgrade gate below makes us stay
                // pinned longer each time. A long-stable upgrade resets it.
                peer.flaps = match peer.last_upgrade {
                    Some(up) if now.duration_since(up) < Duration::from_secs(20) => (peer.flaps + 1).min(5),
                    _ => 0,
                };
                peer.pinned_at = Some(now);
                peer.last_recv = Some(now); // grace before the next check
                peer.last_recv_direct = None; // upgrade needs *new* direct evidence
                if self.own_pub.as_bytes() < &peer.pubkey
                    && emit_rekey(peer, &self.udp, self.force_relay, &self.relay_out, &mut self.index_map).await
                {
                    peer.init_sent_at = Some(now);
                }
            }
            // Upgrade: a pinned peer whose DIRECT path started delivering
            // authenticated packets again leaves the relay. Gated on fresh direct
            // evidence AND a minimum pin time that grows with the flap count
            // (1,2,4,…,32s) — so a path that recovers then dies right back never
            // wins the upgrade, and the peer settles on the stable relay.
            let min_pin = Duration::from_secs(1u64 << peer.flaps.min(5));
            if peer.relay_pinned
                && peer
                    .last_recv_direct
                    .map(|t| now.duration_since(t) < Duration::from_secs(LIVENESS_DEAD_SECS))
                    .unwrap_or(false)
                && peer.pinned_at.map(|p| now.duration_since(p) >= min_pin).unwrap_or(true)
            {
                peer.relay_pinned = false;
                peer.prefer_relay = false;
                peer.last_upgrade = Some(now);
                tracing::info!("direct path recovered; upgrading off relay");
            }
            // Proactive GAPLESS rekey (forward secrecy + nonce safety): the
            // initiator re-keys a session older than REKEY_AFTER_SECS over its
            // CURRENT path, keeping the live session encrypting until the new one
            // is confirmed (handle_handshake_response).
            if self.own_pub.as_bytes() < &peer.pubkey
                && peer
                    .handshake_at
                    .map(|t| now.duration_since(t) >= Duration::from_secs(REKEY_AFTER_SECS))
                    .unwrap_or(false)
            {
                peer.handshake_at = Some(now);
                if emit_rekey(peer, &self.udp, self.force_relay, &self.relay_out, &mut self.index_map).await {
                    tracing::info!("gapless rekey (session aged out)");
                }
            }
        }
    }

    async fn on_udp_in(&mut self, from: SocketAddr, bytes: &[u8], dbuf: &mut [u8]) {
        if let Some(body) = bytes.strip_prefix(DISCO_MAGIC) {
            if let Ok((msg, _)) = Disco::decode(body) {
                self.on_disco(from, msg).await;
            }
            return;
        }
        // wg packet: INIT → decrypt-to-identify the peer; RESP/DATA → find the peer
        // by the receiver index WE assigned (this worker's shard).
        if bytes.first().copied().unwrap_or(0) == T_HANDSHAKE_INIT {
            self.accept(bytes, Some(from), "udp-direct").await;
        } else {
            let idx = if bytes.first() == Some(&T_HANDSHAKE_RESP) {
                le_u32(bytes, 8)
            } else {
                le_u32(bytes, 4)
            };
            let pos = idx
                .and_then(|i| self.index_map.get(i))
                .and_then(|pk| self.peers.iter().position(|p| p.pubkey == pk));
            if let Some(pos) = pos {
                self.deliver_wg(pos, bytes, Some(from), "udp-direct", dbuf).await;
            }
        }
    }

    async fn on_relay_in(&mut self, src: [u8; 32], bytes: &[u8], dbuf: &mut [u8]) {
        // Relay frames carry the peer pubkey, so route by it directly.
        if bytes.first().copied().unwrap_or(0) == T_HANDSHAKE_INIT {
            self.accept(bytes, None, "relay").await;
        } else if let Some(pos) = self.peers.iter().position(|p| p.pubkey == src) {
            self.deliver_wg(pos, bytes, None, "relay", dbuf).await;
        }
    }

    async fn on_tcp_in(&mut self, src: [u8; 32], bytes: &[u8], dbuf: &mut [u8]) {
        // TCP-direct frames carry the connection's peer pubkey (same as the relay
        // path); `from = None` so replies return over this transport.
        if bytes.first().copied().unwrap_or(0) == T_HANDSHAKE_INIT {
            self.accept(bytes, None, "tcp-direct").await;
        } else if let Some(pos) = self.peers.iter().position(|p| p.pubkey == src) {
            self.deliver_wg(pos, bytes, None, "tcp-direct", dbuf).await;
        }
    }

    /// Handle a handshake INIT arriving over any transport (decrypt-to-identify).
    async fn accept(&mut self, bytes: &[u8], from: Option<SocketAddr>, via: &'static str) {
        accept_init(
            &mut self.peers,
            &self.own_priv,
            self.own_pub,
            bytes,
            from,
            via,
            &self.udp,
            self.force_relay,
            &self.relay_out,
            &mut self.index_map,
        )
        .await;
    }

    /// Decrypt an inbound RESP/DATA for `peers[pos]`; forward any plaintext to the TUN.
    async fn deliver_wg(
        &mut self,
        pos: usize,
        bytes: &[u8],
        from: Option<SocketAddr>,
        via: &'static str,
        dbuf: &mut [u8],
    ) {
        if let Some(pkt) = handle_wg(
            &mut self.peers[pos],
            bytes,
            from,
            via,
            &self.udp,
            self.force_relay,
            &self.relay_out,
            dbuf,
        )
        .await
        {
            let _ = self.tun_out.send(pkt).await;
        }
    }

    async fn on_disco(&mut self, from: SocketAddr, msg: Disco) {
        match msg {
            Disco::Ping { tx_id, sender } => {
                let _ = self
                    .udp
                    .send_to(&disco_dgram(&Disco::Pong { tx_id, observed: from }), from)
                    .await;
                // Learn the sender's REACHABLE address by identity (its pubkey),
                // not the advertised candidate — works through a symmetric NAT,
                // where the source port differs per destination.
                if let Some(peer) = self.peers.iter_mut().find(|p| p.pubkey == sender) {
                    peer.direct_addr = Some(from);
                    if !peer.relay_pinned {
                        peer.prefer_relay = false;
                    }
                    if !peer.disco_validated {
                        peer.disco_validated = true;
                        tracing::info!(%from, "disco: learned peer address from its ping");
                    }
                }
            }
            Disco::Pong { .. } => {
                let hit = self
                    .peers
                    .iter_mut()
                    .find(|p| p.candidates.contains(&from) || p.direct_addr == Some(from));
                if let Some(peer) = hit {
                    peer.direct_addr = Some(from);
                    if !peer.relay_pinned {
                        if peer.prefer_relay {
                            tracing::info!(%from, "disco validated direct; upgrading off relay");
                        }
                        peer.prefer_relay = false;
                    }
                    if !peer.disco_validated {
                        peer.disco_validated = true;
                        tracing::info!(%from, "disco: direct path validated");
                    }
                }
            }
            _ => {}
        }
    }

    fn on_tcp_conn(&mut self, pk: [u8; 32], conn_gen: u64, out: Option<mpsc::Sender<Vec<u8>>>) {
        // Honor the generation: a newer connection wins, and a stale "down"
        // (gen < current) is ignored so it can't clobber a live redial.
        if let Some(peer) = self.peers.iter_mut().find(|p| p.pubkey == pk) {
            match out {
                Some(tx) => {
                    peer.tcp_out = Some(tx);
                    peer.tcp_gen = conn_gen;
                    tracing::info!(peer = %hex::encode(&pk[..4]), conn = conn_gen, "tcp-direct up");
                }
                None if peer.tcp_gen == conn_gen => {
                    peer.tcp_out = None;
                    tracing::info!(peer = %hex::encode(&pk[..4]), conn = conn_gen, "tcp-direct down");
                }
                None => {} // stale older connection closing; ignore
            }
        }
    }

    /// Reconcile: bring up a newly-joined peer (REVOKE-1). Builds the session, opens
    /// the hole (disco ping to its candidates), and — if we're the keyed initiator —
    /// sends the first handshake init, exactly like the initial setup loop.
    async fn on_add_peer(
        &mut self,
        pubkey: [u8; 32],
        candidates: Vec<SocketAddr>,
        allowed_ips: Vec<String>,
        initiator: bool,
    ) {
        if self.peers.iter().any(|p| p.pubkey == pubkey) {
            return; // already have it (idempotent re-add)
        }
        let stat = PeerStat::new(allowed_ips);
        self.status.write().insert(pubkey, stat.clone());
        let mut peer = Peer::fresh(pubkey, candidates, self.force_relay, stat);
        if !self.force_relay {
            for c in &peer.candidates {
                let _ = self.udp.send_to(&self.ping, *c).await;
            }
        }
        if initiator {
            let peer_pub = PublicKey::from(peer.pubkey);
            match peer.raw.init_handshake(self.own_priv.clone(), peer_pub) {
                Ok(init) => {
                    if let Some(idx) = le_u32(&init, 4) {
                        self.index_map.insert(idx, peer.pubkey);
                    }
                    send_to_peer(&self.udp, &peer, self.force_relay, &self.relay_out, &init).await;
                    peer.init_sent_at = Some(Instant::now());
                    peer.init_packet = Some(init);
                }
                Err(e) => tracing::error!(error = ?e, "add_peer: init_handshake failed"),
            }
        }
        tracing::info!(peer = %hex::encode(&pubkey[..4]), initiator, "peer added (reconcile)");
        self.peers.push(peer);
    }

    /// Reconcile: drop a revoked peer (REVOKE-1) — remove its session + index routes.
    /// After this the worker holds no key for it, so its traffic can't be decrypted
    /// and a fresh init from it is ignored (`accept_init` requires a known peer).
    fn on_remove_peer(&mut self, pk: [u8; 32]) {
        let before = self.peers.len();
        self.peers.retain(|p| p.pubkey != pk);
        if self.peers.len() != before {
            self.index_map.remove_peer(pk);
            self.status.write().remove(&pk);
            tracing::info!(peer = %hex::encode(&pk[..4]), "peer removed (revoked)");
        }
    }

    /// Reconcile: a peer re-reported its endpoint set. Swap its disco candidates and
    /// re-open the hole toward them, but KEEP the live wg session + receiver index —
    /// so its in-flight DATA (still carrying the index we assigned) keeps routing,
    /// and roaming/disco adopts the working endpoint. Replacing the session here (the
    /// old remove+add) silently desynced the index on every endpoint change.
    async fn on_update_candidates(&mut self, pubkey: [u8; 32], candidates: Vec<SocketAddr>) {
        let Some(peer) = self.peers.iter_mut().find(|p| p.pubkey == pubkey) else {
            return;
        };
        peer.candidates = candidates.clone();
        peer.disco_validated = false; // re-validate against the new endpoints
        if !self.force_relay {
            for c in &candidates {
                let _ = self.udp.send_to(&self.ping, *c).await;
            }
        }
        tracing::info!(peer = %hex::encode(&pubkey[..4]), n = candidates.len(), "peer endpoints updated (reconcile, session kept)");
    }

    async fn on_tun_egress(&mut self, pk: [u8; 32], pkt: &[u8], ebuf: &mut [u8], gso: &mut crate::gso::GsoBatch) {
        let Some(peer) = self.peers.iter_mut().find(|p| p.pubkey == pk && p.handshaked) else {
            return;
        };
        let Ok(enc) = peer.raw.on_send(pkt, ebuf) else {
            return;
        };
        // If the session needs (re)keying, encapsulate emits a handshake INIT
        // instead of data — a different size, not batchable. Only the designated
        // initiator (own_pub < peer, the SAME gate emit_rekey + the keepalive path
        // use) may drive it: otherwise BOTH ends rekey-init an aged session
        // (crossed handshakes), and the responder's accept_init rebuilds a FRESH
        // Cryptor that discards the live session — the peer keeps sending the old
        // receiver index, which now routes to nowhere → silent → relay flap. That
        // desync collapses every multi-peer mesh under rekey churn. The responder
        // drops the init here; its packet stays queued in the crypto layer until
        // the initiator's gapless rekey lands.
        if enc.first() == Some(&T_HANDSHAKE_INIT) {
            if self.own_pub.as_bytes() < &peer.pubkey {
                if let Some(idx) = le_u32(enc, 4) {
                    self.index_map.insert(idx, pk);
                }
                gso.flush(&self.udp).await;
                send_to_peer(&self.udp, peer, self.force_relay, &self.relay_out, enc).await;
            }
            // Responder: drop the init (the initiator drives rekeys); our packet
            // stays queued in the crypto layer until the new session lands.
            return;
        }
        // Data packet out — count wire bytes (like wg transfer).
        peer.stat.add_tx(enc.len());
        // Coalesce DATA into a GSO batch only on the udp-direct path (GSO is
        // UDP-only); the ladder (tcp-direct / relay) sends each individually.
        if !self.force_relay
            && !peer.prefer_relay
            && let Some(addr) = peer.direct_addr
        {
            gso.push(&self.udp, addr, enc).await;
        } else {
            gso.flush(&self.udp).await;
            send_to_peer(&self.udp, peer, self.force_relay, &self.relay_out, enc).await;
        }
    }
}
