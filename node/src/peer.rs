//! Per-peer wg session state + handshake/data handling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fp_crypto::RawCryptor;
use fp_crypto::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::relay::RelayOut;
use crate::util::{T_DATA, T_HANDSHAKE_RESP, le_u32};

/// Per-peer wg session + path state.
pub(crate) struct Peer {
    pub(crate) pubkey: [u8; 32],
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) raw: RawCryptor,
    pub(crate) direct_addr: Option<SocketAddr>,
    pub(crate) prefer_relay: bool,
    /// Reply over TCP-direct (the middle rung) rather than UDP — set when we
    /// last received authenticated data over the peer's TCP-direct connection
    /// (UDP-direct is evidently blocked). Distinct from `prefer_relay`: without it,
    /// receiving over the relay and over TCP-direct were indistinguishable, so a
    /// dead-but-open TCP-direct connection kept eating packets instead of falling
    /// through to the relay (the double-NAT "stuck on tcp-direct" bug).
    pub(crate) prefer_tcp: bool,
    pub(crate) disco_validated: bool,
    pub(crate) handshaked: bool,
    pub(crate) init_packet: Option<Vec<u8>>,
    /// The peer's last INIT we accepted + the RESP we sent — to resend the SAME
    /// resp for a retransmitted (identical) init instead of churning the session.
    pub(crate) last_init: Option<Vec<u8>>,
    pub(crate) last_resp: Option<Vec<u8>>,
    pub(crate) retries: u32,
    /// When we last received an *authenticated* packet from this peer — drives
    /// liveness-based relay fallback when a direct path silently dies (e.g. a
    /// symmetric NAT stops forwarding).
    pub(crate) last_recv: Option<Instant>,
    /// Set once liveness declares the direct *data* path dead and we re-handshake
    /// over the relay. Pins this peer to the relay so disco — which can keep
    /// validating a control path that the data session can't use (crossed
    /// sessions behind one symmetric NAT) — can't flip us back and oscillate.
    pub(crate) relay_pinned: bool,
    /// When we last received an authenticated packet specifically over the
    /// *direct* (UDP) path. Distinct from `last_recv` (any path): a pinned peer
    /// upgrades off the relay only on fresh DIRECT evidence — honest, so it never
    /// oscillates the way disco-based validation does.
    pub(crate) last_recv_direct: Option<Instant>,
    /// Relay-pin hysteresis. When we last pinned to relay (`pinned_at`), when we
    /// last upgraded off it (`last_upgrade`), and a consecutive-flap counter. A
    /// direct path that keeps dying right after it recovers (a double-NAT'd peer
    /// whose symmetric NAT remaps the port) would otherwise oscillate pin↔upgrade
    /// every few seconds; instead each flap makes the peer stay pinned longer
    /// before it may upgrade, so it converges to the stable relay.
    pub(crate) pinned_at: Option<Instant>,
    pub(crate) last_upgrade: Option<Instant>,
    pub(crate) flaps: u32,
    /// Outbound channel to this peer's direct TCP connection (the middle
    /// rung), `Some` while a TCP-direct connection is up — used when UDP-direct is
    /// blocked but the peer is still TCP-reachable, preferred over the relay.
    pub(crate) tcp_out: Option<mpsc::Sender<Vec<u8>>>,
    /// Generation of the TCP-direct connection currently in `tcp_out`, so a
    /// dropped older connection's "down" can't clear a freshly-redialed one.
    pub(crate) tcp_gen: u64,
    /// When the current wg session was established — drives proactive rekey of an
    /// aged session (REKEY_AFTER_SECS) for forward secrecy + nonce safety.
    pub(crate) handshake_at: Option<Instant>,
    /// Smoothed round-trip estimate (handshake init→resp). Scales the liveness
    /// timers so a high-RTT WAN path isn't declared dead before keepalives can
    /// arrive — without this the path-state machine thrashes over the internet.
    pub(crate) rtt: Option<Duration>,
    /// When we last sent a handshake init, to sample RTT on completion.
    pub(crate) init_sent_at: Option<Instant>,
    /// Shared live counters + status for this peer (read by the status socket /
    /// `fluxpeer show`; the same Arc lives in the [`crate::status::StatusRegistry`]).
    pub(crate) stat: Arc<crate::status::PeerStat>,
}

impl Peer {
    /// A fresh peer with no session yet, ready to handshake. `force_relay` skips the
    /// direct path entirely (relay-only). Shared by the initial setup and the live
    /// add path (REVOKE-1 reconcile) so both build identical state.
    pub(crate) fn fresh(
        pubkey: [u8; 32],
        candidates: Vec<SocketAddr>,
        force_relay: bool,
        stat: Arc<crate::status::PeerStat>,
    ) -> Self {
        Peer {
            pubkey,
            direct_addr: if force_relay { None } else { candidates.first().copied() },
            candidates,
            raw: RawCryptor::new::<fp_crypto_noise::Cryptor>(),
            prefer_relay: force_relay,
            prefer_tcp: false,
            disco_validated: false,
            handshaked: false,
            init_packet: None,
            last_init: None,
            last_resp: None,
            retries: 0,
            last_recv: None,
            relay_pinned: false,
            last_recv_direct: None,
            pinned_at: None,
            last_upgrade: None,
            flaps: 0,
            tcp_out: None,
            tcp_gen: 0,
            handshake_at: None,
            rtt: None,
            init_sent_at: None,
            stat,
        }
    }

    /// Fold a fresh RTT sample (init→resp) into the smoothed estimate.
    pub(crate) fn note_rtt(&mut self) {
        if let Some(t) = self.init_sent_at.take() {
            let sample = Instant::now().duration_since(t);
            self.rtt = Some(match self.rtt {
                Some(r) => (r * 4 + sample) / 5,
                None => sample,
            });
        }
    }
}

/// Send a wg packet to one peer down the ladder: UDP-direct → TCP-direct → relay.
pub(crate) async fn send_to_peer(
    udp: &UdpSocket,
    peer: &Peer,
    force_relay: bool,
    relay_out: &Option<RelayOut>,
    bytes: &[u8],
) {
    if !force_relay
        && !peer.prefer_relay
        && !peer.prefer_tcp
        && let Some(addr) = peer.direct_addr
    {
        let _ = udp.send_to(bytes, addr).await;
    } else if !force_relay && !peer.prefer_relay && let Some(tx) = &peer.tcp_out {
        // TCP-direct: try_send (drop-on-full), wg retransmits any dropped frame.
        // Gated on !prefer_relay so a dead-but-open TCP connection doesn't swallow
        // packets when liveness/relay-receipt says to use the relay.
        let _ = tx.try_send(bytes.to_vec());
    } else if let Some(tx) = relay_out {
        // try_send (drop-on-full), never await: a relay mid-failover must not
        // stall the single-task data plane. wg retransmits any dropped frame.
        let _ = tx.try_send((peer.pubkey, bytes.to_vec()));
    } else if let Some(addr) = peer.direct_addr {
        let _ = udp.send_to(bytes, addr).await; // last resort
    }
}

/// Handle a handshake INIT: decrypt it to learn WHICH peer sent it (its static
/// pubkey), so it routes by identity — not source address, which a NAT rewrites
/// (the #2 fix). Adopts a fresh session for that peer (supports re-key), replies,
/// and records our session index so the peer's later DATA routes by index.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn accept_init(
    peers: &mut [Peer],
    own_priv: &StaticSecret,
    own_pub: PublicKey,
    bytes: &[u8],
    from: Option<SocketAddr>,
    via: &'static str,
    udp: &UdpSocket,
    force_relay: bool,
    relay_out: &Option<RelayOut>,
    index_map: &mut crate::worker::IndexTable,
) {
    // Retransmitted (byte-identical) init we already answered → resend the SAME
    // resp and keep the existing session, instead of building a new one the
    // initiator won't use.
    if let Some(peer) = peers.iter().find(|p| p.last_init.as_deref() == Some(bytes)) {
        if let Some(resp) = peer.last_resp.clone() {
            send_to_peer(udp, peer, force_relay, relay_out, &resp).await;
        }
        return;
    }
    // Gapless rekey (responder): if this init is from a peer we ALREADY have a
    // live session with, peek its pubkey (no state advance) and process the init
    // on the EXISTING session — the new key lands in a fresh slot while the old
    // keeps decrypting in-flight data. Only a genuinely NEW peer rebuilds.
    let rekey_pk = fp_crypto_noise::peek_init_pubkey(own_priv, &own_pub, bytes)
        .filter(|pk| peers.iter().any(|p| &p.pubkey == pk && p.handshaked));
    if let Some(pk) = rekey_pk
        && let Some(peer) = peers.iter_mut().find(|p| p.pubkey == pk)
    {
        let mut rbuf = [0u8; 256];
        match peer.raw.rekey_respond(bytes, &mut rbuf) {
            Ok(resp_opt) => {
                peer.last_init = Some(bytes.to_vec());
                set_path(peer, from, via);
                peer.last_recv = Some(Instant::now());
                peer.handshake_at = Some(Instant::now());
                peer.stat.mark_handshake();
                if let Some(resp) = resp_opt {
                    let resp = resp.to_vec();
                    peer.last_resp = Some(resp.clone());
                    if let Some(idx) = le_u32(&resp, 4) {
                        index_map.insert(idx, pk);
                    }
                    send_to_peer(udp, peer, force_relay, relay_out, &resp).await;
                }
                tracing::info!(via, "gapless rekey (responder)");
                return;
            }
            // Fall through to a fresh handshake on error (rare).
            Err(e) => tracing::debug!(error = ?e, "rekey_respond; rebuilding"),
        }
    }
    // New init: decrypt to learn the sender's static pubkey (route by identity,
    // not source address — the #2 fix), adopt a fresh session, reply.
    let mut fresh = RawCryptor::new::<fp_crypto_noise::Cryptor>();
    let resp_opt = match fresh.handle_handshake(own_priv.clone(), own_pub, bytes) {
        Ok(r) => r,
        Err(e) => return tracing::debug!(error = ?e, "accept_init: handle_handshake failed"),
    };
    let Ok(peer_pub) = fresh.get_peer_public() else { return };
    let pk = *peer_pub.as_bytes();
    let Some(peer) = peers.iter_mut().find(|p| p.pubkey == pk) else {
        return;
    };
    peer.raw = fresh;
    peer.last_init = Some(bytes.to_vec());
    set_path(peer, from, via);
    peer.handshaked = true;
    peer.last_recv = Some(Instant::now());
    peer.handshake_at = Some(Instant::now());
    peer.stat.mark_handshake();
    if let Some(resp) = resp_opt {
        peer.last_resp = Some(resp.clone());
        if let Some(idx) = le_u32(&resp, 4) {
            index_map.insert(idx, pk);
        }
        send_to_peer(udp, peer, force_relay, relay_out, &resp).await;
    }
    tracing::info!(via, "handshake complete (responder)");
}

/// Handle an inbound RESP or DATA for a KNOWN `peer`. Returns a decrypted IP
/// packet for the TUN, if any. (INIT is handled by [`accept_init`].)
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_wg(
    peer: &mut Peer,
    bytes: &[u8],
    from: Option<SocketAddr>,
    via: &'static str,
    udp: &UdpSocket,
    force_relay: bool,
    relay_out: &Option<RelayOut>,
    dbuf: &mut [u8],
) -> Option<Vec<u8>> {
    match bytes.first().copied().unwrap_or(0) {
        T_HANDSHAKE_RESP => match peer.raw.handle_handshake_response(bytes) {
            Ok(()) => {
                set_path(peer, from, via);
                peer.handshaked = true;
                peer.last_recv = Some(Instant::now());
                peer.handshake_at = Some(Instant::now());
                peer.stat.mark_handshake();
                peer.note_rtt();
                tracing::info!(
                    via,
                    rtt_ms = peer.rtt.map(|r| r.as_millis()),
                    "handshake complete (initiator)"
                );
                // WireGuard: the initiator sends a keepalive so the responder
                // receives transport data and confirms its own send-session —
                // otherwise the responder can't send first (the #1 fix).
                let mut kbuf = [0u8; 128];
                if let Ok(ka) = peer.raw.on_send(&[], &mut kbuf) {
                    send_to_peer(udp, peer, force_relay, relay_out, ka).await;
                }
            }
            Err(e) => tracing::debug!(error = ?e, "handle_handshake_response"),
        },
        T_DATA => match peer.raw.on_recv(bytes, dbuf) {
            Ok(pkt) => {
                // WireGuard endpoint roaming: a decrypted (AEAD-authenticated)
                // packet proves the peer's *current* source address, so adopt it
                // for replies. This follows a symmetric NAT that remaps the port
                // per-flow/timeout — without it we keep replying to a stale
                // disco-learned port and the link silently dies.
                set_path(peer, from, via);
                peer.last_recv = Some(Instant::now());
                // Count wire bytes received (incl. keepalives), like wg transfer.
                peer.stat.add_rx(bytes.len());
                // An empty payload is a keepalive — confirms the session, not a real packet.
                if !pkt.is_empty() {
                    return Some(pkt.to_vec());
                }
            }
            Err(e) => tracing::debug!(error = ?e, "on_recv"),
        },
        _ => {}
    }
    None
}

/// A wg packet arrived for this peer — adopt the transport it came on for replies,
/// so the ladder (UDP-direct → TCP-direct → relay) follows what actually works.
/// `via` is the inbound rung; `from` is the source addr for UDP-direct (roaming).
pub(crate) fn set_path(peer: &mut Peer, from: Option<SocketAddr>, via: &str) {
    match via {
        // UDP-direct: roam to the current source + record direct-path liveness, but
        // never un-pin a peer whose direct *data* path was declared dead
        // (relay_pinned) — only the tick's re-probe does that.
        "udp-direct" => {
            if let Some(f) = from {
                peer.direct_addr = Some(f);
            }
            peer.last_recv_direct = Some(Instant::now());
            peer.prefer_tcp = false;
            if !peer.relay_pinned {
                peer.prefer_relay = false;
            }
        }
        // TCP-direct: the peer reaches us over TCP (UDP is blocked) — reply over TCP,
        // not the relay. Follows the peer off the relay too (unless hard-pinned).
        "tcp-direct" => {
            peer.prefer_tcp = true;
            if !peer.relay_pinned {
                peer.prefer_relay = false;
            }
        }
        // Relay: the peer is reaching us via the relay → reply via the relay.
        _ => peer.prefer_relay = true,
    }
}
