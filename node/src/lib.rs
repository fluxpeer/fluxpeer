//! fluxpeer node (`fp-node`): a runnable mesh node. Pulls its config from the
//! control-server, creates a TUN, installs split-tunnel routes, and maintains a
//! WireGuard session with EACH peer in the network — direct (UDP, disco-punched)
//! where possible, else over the relay-server. Proves the coordinated mesh data
//! plane end to end.
//!
//! Engine = the real wg tunnel (fp-crypto-noise = BoringTun). Per peer: report
//! own endpoint + read peers' endpoints (A4.1), disco-probe on the shared UDP
//! socket (A4.3), relay fallback + upgrade (A4.4), AnyTLS/443 relay (A4.5).
//! Multi-peer (A4.7): N peers, each its own wg session, routed by allowed_ips;
//! one relay connection multiplexes all peers by pubkey, and each peer gets its
//! own TCP-direct connection (middle rung) with bidirectional liveness +
//! relay fallback.
//!
//! Split-tunnel BY DESIGN: only the overlay subnet + peers' allowed_ips are
//! routed into the TUN — never 0.0.0.0/0.
//!
//! Usage:
//! fp-node keygen # print a fresh hex keypair
//! sudo fp-node run <config.json> # bring up the tunnels (needs root for TUN)

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fp_crypto::x25519::{PublicKey, StaticSecret};
use fp_disco::Disco;
use fp_tun::TunPacket;
use fp_tun::Device; // brings the `.name()` method on the concrete device into scope
use futures::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

mod config;
mod control;
mod daemon;
mod gso;
mod join;
mod show;
mod status;
mod statusd;
mod peer;
mod relay;
mod route;
mod tcp_direct;
mod util;
mod worker;

use config::Config;
use control::{fetch_relays, resolve_from_control, stun_query};
use peer::{Peer, send_to_peer};
use relay::{RelayIn, RelayOut, RelayTarget, relay_supervisor};
use tcp_direct::{TcpConn, TcpIn, tcp_direct_manager};
use util::{disco_dgram, hex32, le_u32, local_ipv4_toward, netmask_v4, url_host};

/// Routing tables the central readers consult per packet. Behind `RwLock` so the
/// reconcile loop (REVOKE-1) can mutate membership live; reads are brief and dropped
/// before any await.
type WidMap = Arc<parking_lot::RwLock<std::collections::HashMap<[u8; 32], usize>>>;
type CandMap = Arc<parking_lot::RwLock<std::collections::HashMap<SocketAddr, usize>>>;
type AllowedMap = Arc<parking_lot::RwLock<Vec<(Vec<String>, [u8; 32], usize)>>>;

/// Steady-state membership reconcile (REVOKE-1). Polls the control-server's
/// `device_config`; when its `config_epoch` advances (a device was revoked or a new
/// one enrolled), diffs the peer set against `known` and adds/removes peers LIVE —
/// routing tables + worker sessions + TUN routes — with no node restart. A revoked
/// peer's session is dropped within one poll (~2s) so it can no longer send or
/// receive (fail-closed). Endpoint-only roaming is left to wg/disco; the tcp-direct
/// middle rung is not live-updated (a new peer still gets udp-direct + relay).
struct Reconciler {
    client: fluxpeer_sdk::Client,
    device_id: String,
    tun_name: String,
    n: usize,
    own_pub: PublicKey,
    peer_to_wid: WidMap,
    cand_to_wid: CandMap,
    allowed: AllowedMap,
    wtxs: Vec<mpsc::Sender<worker::WorkerMsg>>,
    known: std::collections::HashMap<[u8; 32], (usize, Vec<SocketAddr>, Vec<String>)>,
    last_epoch: u64,
    ordinal: usize,
    // Full-tunnel (exit node) re-evaluation: re-apply or tear down 0.0.0.0/0 routing
    // when a peer becomes / stops being an exit (e.g. a 0.0.0.0/0 route is approved
    // live). Shared `exit_state` so the SIGTERM handler restores routing on shutdown.
    exit_state: ExitState,
    control_host: String,
    relay_ips: Vec<String>,
    exclude_routes: Vec<String>,
    dns_override: Vec<String>,
}

use route::{route_del, route_replace};

/// Two candidate-endpoint sets are equal regardless of order.
fn same_endpoints(a: &[SocketAddr], b: &[SocketAddr]) -> bool {
    a.len() == b.len() && {
        let s: std::collections::HashSet<&SocketAddr> = a.iter().collect();
        b.iter().all(|x| s.contains(x))
    }
}

/// Live full-tunnel teardown state, shared between the Reconciler (which sets it as
/// 0.0.0.0/0 appears/leaves) and the SIGTERM handler (which restores routing/DNS).
type ExitState = Arc<parking_lot::Mutex<Option<(String, Vec<String>)>>>;

/// Apply full-tunnel exit routing for `peers` on `dev`: if a peer routes 0.0.0.0/0,
/// install the split-default + bypass routes (wg carrier, local LAN, control-server,
/// user excludes) + DNS, returning the teardown `(dev, bypass)`; else None.
fn apply_exit(
    peers: &[control::PeerInfo],
    dev: &str,
    control_host: &str,
    relay_ips: &[String],
    exclude_routes: &[String],
    dns_override: &[String],
) -> Option<(String, Vec<String>)> {
    let ex = peers.iter().find(|p| p.allowed_ips.iter().any(|c| c == "0.0.0.0/0"))?;
    let (gw, phys) = match (route::default_gateway(), route::physical_iface()) {
        (Some(g), Some(p)) => (g, p),
        _ => {
            tracing::warn!("exit peer present but no physical default gateway/iface — full-tunnel not applied");
            return None;
        }
    };
    // Candidate bypass targets: the control-server, relays, the exit peer's own
    // endpoint(s), and the user's split-exclude CIDRs. The local LAN is NOT listed
    // — its connected route already beats 0.0.0.0/1 (and pinning it via the gateway
    // would break on-link reachability). Only REMOTE targets (via the default
    // gateway) actually need pinning; on-link ones are already excluded.
    let mut candidates: Vec<String> = vec![control_host.to_string()];
    candidates.extend(relay_ips.iter().cloned());
    for c in &ex.candidates {
        candidates.push(c.ip().to_string());
    }
    candidates.extend(exclude_routes.iter().cloned());
    candidates.sort();
    candidates.dedup();
    let bypass: Vec<String> = candidates.into_iter().filter(|c| route::needs_bypass(c)).collect();
    let dns = if !dns_override.is_empty() {
        dns_override.first().cloned()
    } else {
        ex.overlay.map(|a| a.to_string())
    };
    route::exit_up(dev, &gw, &phys, &bypass, dns.as_deref());
    Some((dev.to_string(), bypass))
}

impl Reconciler {
    async fn run(mut self) {
        let mut iv = tokio::time::interval(Duration::from_secs(2));
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            iv.tick().await;
            let Some(desired) =
                control::poll_peers_if_changed(&self.client, &self.device_id, &mut self.last_epoch).await
            else {
                continue;
            };
            let desired_snapshot = desired.clone(); // for the exit-node re-eval below
            let desired_set: std::collections::HashSet<[u8; 32]> = desired.iter().map(|p| p.pubkey).collect();
            // Removed (revoked): known, gone from desired. Drop the session first.
            let removed: Vec<[u8; 32]> = self.known.keys().copied().filter(|pk| !desired_set.contains(pk)).collect();
            for pk in removed {
                self.remove_peer(pk).await;
            }
            // Added (newly enrolled) / endpoint changes (a peer restarted or roamed
            // and re-reported its endpoint) / route changes (approved subnet route →
            // AllowedIPs changed) all applied live, no restart.
            for pi in desired {
                let entry = self.known.get(&pi.pubkey).map(|(_, c, a)| (c.clone(), a.clone()));
                match entry {
                    None => self.add_peer(pi).await,
                    // Endpoint set changed (peer roamed/restarted): update its disco
                    // candidates IN PLACE so probes reach the new endpoint, but KEEP
                    // the live wg session + receiver index. The old remove+add tore
                    // the session down, discarding our index while the peer kept
                    // sending it → its DATA routed to nowhere → silent → relay flap.
                    // A genuinely restarted peer re-initiates itself (`accept_init`).
                    Some((cands, _)) if !same_endpoints(&cands, &pi.candidates) => {
                        self.update_candidates(pi).await;
                    }
                    Some((_, aips)) if aips != pi.allowed_ips => self.update_routes(pi),
                    Some(_) => {}
                }
            }
            self.sync_exit(&desired_snapshot);
        }
    }

    /// An existing peer's AllowedIPs changed (a subnet route was approved/removed) —
    /// swap its routing-table entry + install/remove the TUN routes live. SYNC (no
    /// await across the RwLock guards).
    /// Re-evaluate full-tunnel: bring exit routing up when a peer becomes an exit
    /// (0.0.0.0/0 appears, e.g. an approved route arrives live) or tear it down when
    /// none remains. Idempotent; the shared `exit_state` lets the SIGTERM handler
    /// restore routing on shutdown.
    fn sync_exit(&self, peers: &[control::PeerInfo]) {
        let has_exit = peers.iter().any(|p| p.allowed_ips.iter().any(|c| c == "0.0.0.0/0"));
        let mut st = self.exit_state.lock();
        match (has_exit, st.is_some()) {
            (true, false) => {
                *st = apply_exit(
                    peers,
                    &self.tun_name,
                    &self.control_host,
                    &self.relay_ips,
                    &self.exclude_routes,
                    &self.dns_override,
                );
            }
            (false, true) => {
                if let Some((dev, bypass)) = st.take() {
                    route::exit_down(&dev, &bypass);
                }
            }
            _ => {}
        }
    }

    fn update_routes(&mut self, pi: control::PeerInfo) {
        let Some((wid, cands, old_aips)) = self.known.get(&pi.pubkey).cloned() else {
            return;
        };
        {
            let mut a = self.allowed.write();
            a.retain(|(_, p, _)| *p != pi.pubkey);
            a.push((pi.allowed_ips.clone(), pi.pubkey, wid));
        }
        for cidr in &old_aips {
            if !pi.allowed_ips.contains(cidr) {
                route_del(cidr, &self.tun_name);
            }
        }
        for cidr in &pi.allowed_ips {
            if !old_aips.contains(cidr) {
                route_replace(cidr, &self.tun_name);
            }
        }
        tracing::info!(peer = %hex::encode(&pi.pubkey[..4]), "reconcile: peer routes updated");
        self.known.insert(pi.pubkey, (wid, cands, pi.allowed_ips));
    }

    /// Purge a peer's routing entries (SYNC: no `.await`, so the `!Send` RwLock
    /// guards can't cross an await point and taint the spawned future). Returns its
    /// owning worker + allowed-ips for the caller's async teardown.
    fn route_remove(&mut self, pk: [u8; 32]) -> Option<(usize, Vec<String>)> {
        let (wid, cands, aips) = self.known.remove(&pk)?;
        self.peer_to_wid.write().remove(&pk);
        let mut cw = self.cand_to_wid.write();
        for c in &cands {
            cw.remove(c);
        }
        drop(cw);
        self.allowed.write().retain(|(_, p, _)| *p != pk);
        Some((wid, aips))
    }

    /// Insert a peer's routing entries (SYNC, see `route_remove`). Returns its
    /// assigned worker + whether we initiate the handshake.
    fn route_add(&mut self, pi: &control::PeerInfo) -> (usize, bool) {
        let wid = self.ordinal % self.n;
        self.ordinal += 1;
        self.peer_to_wid.write().insert(pi.pubkey, wid);
        let mut cw = self.cand_to_wid.write();
        for c in &pi.candidates {
            cw.insert(*c, wid);
        }
        drop(cw);
        self.allowed.write().push((pi.allowed_ips.clone(), pi.pubkey, wid));
        (wid, self.own_pub.as_bytes() < &pi.pubkey)
    }

    /// Drop a revoked peer: kill its worker session, purge routing, remove TUN routes.
    async fn remove_peer(&mut self, pk: [u8; 32]) {
        let Some((wid, aips)) = self.route_remove(pk) else {
            return;
        };
        let _ = self.wtxs[wid].send(worker::WorkerMsg::RemovePeer(pk)).await;
        for cidr in &aips {
            route_del(cidr, &self.tun_name);
        }
        tracing::info!(peer = %hex::encode(&pk[..4]), "reconcile: peer revoked → session dropped");
    }

    /// Bring up a newly-joined peer: route it, install its TUN route, and hand the
    /// worker an `AddPeer` so it starts handshaking.
    async fn add_peer(&mut self, pi: control::PeerInfo) {
        let (wid, initiator) = self.route_add(&pi);
        for cidr in &pi.allowed_ips {
            route_replace(cidr, &self.tun_name);
        }
        let _ = self.wtxs[wid]
            .send(worker::WorkerMsg::AddPeer {
                pubkey: pi.pubkey,
                candidates: pi.candidates.clone(),
                allowed_ips: pi.allowed_ips.clone(),
                initiator,
            })
            .await;
        tracing::info!(peer = %hex::encode(&pi.pubkey[..4]), "reconcile: peer joined → session added");
        self.known.insert(pi.pubkey, (wid, pi.candidates, pi.allowed_ips));
    }

    /// A known peer re-reported a different endpoint set: re-point its disco
    /// candidates (routing map + worker) WITHOUT tearing down the wg session, so its
    /// receiver index stays registered. See `WorkerMsg::UpdateCandidates`.
    async fn update_candidates(&mut self, pi: control::PeerInfo) {
        let Some((wid, old_cands, aips)) = self.known.get(&pi.pubkey).cloned() else {
            return;
        };
        {
            let mut cw = self.cand_to_wid.write();
            for c in &old_cands {
                cw.remove(c);
            }
            for c in &pi.candidates {
                cw.insert(*c, wid);
            }
        }
        self.known.insert(pi.pubkey, (wid, pi.candidates.clone(), aips));
        let _ = self.wtxs[wid]
            .send(worker::WorkerMsg::UpdateCandidates {
                pubkey: pi.pubkey,
                candidates: pi.candidates,
            })
            .await;
        tracing::info!(peer = %hex::encode(&pi.pubkey[..4]), "reconcile: peer endpoints changed → candidates updated (session kept)");
    }
}

/// Called with every egress socket fd the engine opens so the host can exclude it
/// from the tunnel — on Android `VpnService.protect(fd)`, else the engine's own wg
/// packets would route back INTO the tun (a loop). Desktop/server pass `None`.
pub type ProtectFn = std::sync::Arc<dyn Fn(std::os::fd::RawFd) + Send + Sync>;

/// Bring up the tunnels from a config FILE (desktop/server: we create the device).
pub async fn run(cfg_path: &str) -> std::io::Result<()> {
    let cfg: Config = serde_json::from_slice(&std::fs::read(cfg_path)?)?;
    run_with(cfg, None).await
}

/// EMBEDDED entry (mobile): run the SAME node engine from an inline config JSON,
/// adopting the OS-provided tun fd (Android VpnService / iOS NEPacketTunnelProvider)
/// instead of creating a device. `protect` excludes egress sockets from the VPN.
/// This is what makes a phone a first-class mesh peer — same data plane as the CLI.
pub async fn run_embedded(cfg_json: &str, tun_fd: i32, protect: Option<ProtectFn>) -> std::io::Result<()> {
    let mut cfg: Config = serde_json::from_str(cfg_json).map_err(std::io::Error::other)?;
    cfg.tun_fd = Some(tun_fd);
    run_with(cfg, protect).await
}

async fn run_with(cfg: Config, protect: Option<ProtectFn>) -> std::io::Result<()> {
    let own_priv = StaticSecret::from(hex32(&cfg.private_key));
    let own_pub = PublicKey::from(&own_priv);

    // Bind the wg UDP socket FIRST so STUN learns the NAT mapping for this port.
    // Arc so the data plane can later share one socket across per-core worker
    // tasks (multicore sharding); `&udp` still deref-coerces to `&UdpSocket`.
    let udp = Arc::new(UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.listen_port))).await?);
    // Mobile: exclude our egress socket from the VPN (else wg packets loop into the
    // tun). No-op on desktop/server (protect = None). Relay/tcp-direct sockets are
    // protected the same way where they're opened (see relay/tcp_direct).
    if let Some(p) = &protect {
        use std::os::fd::AsRawFd;
        p(udp.as_raw_fd());
        tracing::info!("protected egress udp socket from VPN");
    }

    // Pull the relay directory from coordination. Local cfg fields, if set, still
    // override it — so a node needs zero relay/STUN config in the common case.
    let relays_dir = fetch_relays(&cfg).await;
    let dir0 = relays_dir.first();
    // Relay candidates for failover: a hand-written cfg.relay overrides the
    // directory entirely; otherwise use every directory relay (dial order).
    let relay_targets: Vec<RelayTarget> = match cfg.relay.as_deref().and_then(|s| s.parse::<SocketAddr>().ok()) {
        Some(a) => vec![RelayTarget {
            addr: a,
            anytls: cfg.relay_anytls,
            bond: cfg.relay_bond,
            bond_links: cfg.relay_bond_links,
            node_id: cfg
                .relay_node_id
                .clone()
                .unwrap_or_else(|| "fluxpeer-relay".to_string()),
        }],
        None => relays_dir
            .iter()
            .filter_map(|d| {
                Some(RelayTarget {
                    addr: d.url.parse().ok()?,
                    anytls: d.anytls,
                    bond: cfg.relay_bond,
                    bond_links: cfg.relay_bond_links,
                    node_id: d.node_id.clone(),
                })
            })
            .collect(),
    };
    let eff_stun: Option<SocketAddr> = cfg
        .stun_server
        .as_deref()
        .and_then(|s| s.parse().ok())
        .or_else(|| dir0.and_then(|d| d.stun));
    if !relays_dir.is_empty() {
        tracing::info!(relays = relays_dir.len(), candidates = relay_targets.len(), stun = ?eff_stun, "relay directory from control-server");
    }

    // Advertised endpoints: explicit, else STUN reflexive (public, NAT-traversable)
    // + local IPv4 (for same-LAN peers). Disco probes all of them.
    let advertise: Vec<String> = if !cfg.advertise.is_empty() {
        cfg.advertise.clone()
    } else {
        let mut a = Vec::new();
        if let Some(stun) = eff_stun
            && let Some(reflexive) = stun_query(&udp, stun).await
        {
            tracing::info!(%reflexive, "STUN: learned reflexive (public) address");
            a.push(reflexive.to_string());
        }
        if let Some(ip) = local_ipv4_toward(&url_host(&cfg.control_server)) {
            a.push(format!("{ip}:{}", cfg.listen_port));
        }
        a
    };

    let (r, init_epoch) = resolve_from_control(&cfg, &advertise).await?;

    // --- TUN: adopt an externally-provided fd (mobile VpnService) OR create + address
    // the device ourselves (desktop/server). With an injected fd the OS already
    // configured address/routes/MTU/DNS, so we ONLY wrap the fd; the data plane below
    // is identical either way. ---
    // EMBEDDED mode = the OS owns the tun (we adopt its fd): true on mobile
    // (Android `VpnService` / iOS `NEPacketTunnelProvider`), where host-level route /
    // DNS / NAT APIs are unavailable to a sandboxed app and the VPN framework already
    // configured the device. `tun_fd` is only ever set on those platforms, so it
    // doubles as the system-type switch; we also log the concrete OS for diagnosis.
    let injected_fd = cfg.tun_fd;
    let embedded = injected_fd.is_some();
    if embedded {
        tracing::info!(os = std::env::consts::OS, "node running EMBEDDED (adopting OS-provided tun fd)");
    }
    let mut tun_cfg = fp_tun::configure();
    if let Some(fd) = injected_fd {
        tun_cfg.raw_fd(fd);
    } else {
        tun_cfg.address(r.own_addr).netmask(netmask_v4(cfg.prefix_len)).up();
        // Linux uses the configured name (fp0); macOS utun names are kernel-assigned
        // (utunN) and "fp0" is rejected, so there we let it auto-assign + read it back.
        #[cfg(not(target_os = "macos"))]
        tun_cfg.name(&cfg.tun_name);
        // MTU: a LOCAL config value (desktop "Settings") overrides the control-server's.
        if let Some(m) = cfg.mtu.or(r.mtu) {
            tun_cfg.mtu(m);
            tracing::info!(mtu = m, "applying MTU");
        }
    }
    let eff_dns: Vec<String> = if cfg.dns.is_empty() { r.dns.clone() } else { cfg.dns.clone() };
    let dev = fp_tun::create_as_async(&tun_cfg).map_err(std::io::Error::other)?;
    // The actual kernel device name — equals cfg.tun_name on Linux, an auto-assigned
    // utunN on macOS. Routes must target THIS; the logical/status name stays tun_name.
    let dev_name = dev.get_ref().name().to_string();
    tracing::info!(tun = %cfg.tun_name, dev = %dev_name, addr = %r.own_addr, peers = r.peers.len(), fd = ?injected_fd, "TUN up");

    let control_host = {
        let ch = url_host(&cfg.control_server);
        ch.split(':').next().unwrap_or(&ch).to_string()
    };
    let relay_ips: Vec<String> = relay_targets.iter().map(|rt| rt.addr.ip().to_string()).collect();

    // Host route/DNS/exit setup — ONLY when we own the device. With an injected fd
    // (mobile VpnService) the OS already installed the address, routes (incl. any
    // 0.0.0.0/0 full-tunnel), MTU and DNS; touching them from here would fail or
    // fight the platform. The data plane below is identical — the phone is a full
    // peer (disco/relay/multi-peer/exit-as-a-peer), just without host-side routing.
    let exit_state: ExitState = if embedded {
        tracing::info!("adopted external tun fd (mobile VpnService); platform owns routes/DNS/exit");
        Arc::new(parking_lot::Mutex::new(None))
    } else {
        apply_dns(&eff_dns, &dev_name);
        for p in &r.peers {
            for cidr in &p.allowed_ips {
                route_replace(cidr, &dev_name); // 0.0.0.0/0 is skipped — handled by apply_exit
            }
        }
        // Catch-all route for the WHOLE overlay subnet → tun, not just per-peer /32s.
        // Traffic to an unallocated overlay IP (e.g..1 with no peer) is then dropped by
        // wg ("no peer matches") instead of LEAKING out the physical default route — these
        // addresses live in the 100.64/10 CGNAT range, which the ISP may actually answer,
        // giving a false "connected" ping. Mirrors the Linux wg-quick connected route +
        // Tailscale "owning" its CGNAT range; macOS utun is point-to-point so it isn't
        // auto-created. A more-specific peer /32 still wins. Never 0.0.0.0/0 (prefix 0).
        if cfg.prefix_len > 0 && cfg.prefix_len <= 32 {
            let mask: u32 = u32::MAX << (32 - cfg.prefix_len);
            let net = Ipv4Addr::from(u32::from(r.own_addr) & mask);
            route_replace(&format!("{net}/{}", cfg.prefix_len), &dev_name);
        }
        // Exit node (full-tunnel): if any peer routes 0.0.0.0/0, send the default over
        // the tun (split-default) + bypass the wg carrier/LAN/control/relay + DNS = the
        // exit's overlay, per the WireGuard exit-node model. Reconciler re-applies live.
        Arc::new(parking_lot::Mutex::new(apply_exit(
            &r.peers,
            &dev_name,
            &control_host,
            &relay_ips,
            &cfg.exclude_routes,
            &eff_dns,
        )))
    };
    // Exit SIDE: if this device is configured as an exit node, enable IPv4
    // forwarding + NAT masquerade so peers' 0.0.0.0/0 traffic actually egresses.
    let exit_gateway_phys: Option<String> = if cfg.exit_node {
        let phys = route::physical_iface();
        if let Some(p) = &phys {
            // WinNAT masquerades by source subnet, so pass the overlay's network
            // prefix (e.g. 100.72.16.0/24). Linux ignores it (it NATs by egress iface).
            let plen = cfg.prefix_len;
            let mask: u32 = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
            let net = Ipv4Addr::from(u32::from(r.own_addr) & mask);
            route::exit_gateway_up(p, &dev_name, &format!("{net}/{plen}"));
        } else {
            tracing::warn!("exit_node set but no physical egress interface found");
        }
        phys
    } else {
        None
    };

    // Graceful teardown: restore the default route + DNS (client side) and the NAT
    // rule (exit side) on SIGTERM/SIGINT before exiting — the daemon sends SIGTERM,
    // then SIGKILL. Without this a killed full-tunnel node strands the box's routing.
    #[cfg(unix)]
    {
        let es = exit_state.clone();
        let gw = exit_gateway_phys.clone();
        let tun = dev_name.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
            let mut intr = signal(SignalKind::interrupt()).expect("SIGINT handler");
            tokio::select! { _ = term.recv() => {}, _ = intr.recv() => {} }
            // Read the CURRENT exit state (the Reconciler keeps it live).
            if let Some((dev, bypass)) = es.lock().take() {
                route::exit_down(&dev, &bypass);
            }
            if let Some(phys) = gw {
                route::exit_gateway_down(&phys, &tun);
            }
            std::process::exit(0);
        });
    }
    // Windows has no SIGTERM/SIGINT; hook Ctrl-C so a foreground node still restores
    // routes/DNS (and the exit-side NAT, when it lands) before exiting.
    #[cfg(windows)]
    {
        let es = exit_state.clone();
        let gw = exit_gateway_phys.clone();
        let tun = dev_name.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            if let Some((dev, bypass)) = es.lock().take() {
                route::exit_down(&dev, &bypass);
            }
            if let Some(phys) = gw {
                route::exit_gateway_down(&phys, &tun);
            }
            std::process::exit(0);
        });
    }

    let (mut tun_tx, mut tun_rx) = dev.into_framed().split();

    // --- Relay: a supervisor keeps ONE connection alive across the candidate
    // list, failing over on dial-failure or drop. It bridges to these stable
    // channels so the data-plane loop never sees a reconnect. ---
    let (relay_in, relay_out): (Option<RelayIn>, Option<RelayOut>) = if relay_targets.is_empty() {
        (None, None)
    } else {
        let (app_in_tx, app_in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
        let (app_out_tx, app_out_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
        tokio::spawn(relay_supervisor(
            relay_targets,
            *own_pub.as_bytes(),
            app_out_rx,
            app_in_tx,
        ));
        (Some(app_in_rx), Some(app_out_tx))
    };

    // --- Build per-peer state, partition across N workers, send first probe ---
    // Worker count: FP_WORKERS override (benchmark/tuning) else cores-1; never
    // more than the peer count (no empty workers) nor less than 1.
    let n = std::env::var("FP_WORKERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|x| x.get().saturating_sub(1))
                .unwrap_or(1)
        })
        .max(1)
        .min(r.peers.len().max(1));
    let ping = disco_dgram(&Disco::Ping {
        tx_id: [0u8; 12],
        sender: *own_pub.as_bytes(),
    });

    // --- TCP-direct (middle rung), multi-peer: each peer gets its own direct
    // TCP connection. We dial peers with a larger pubkey (we're the smaller-keyed
    // initiator); smaller-keyed peers dial us and we accept. ---
    let (tcp_in, tcp_conn_rx): (Option<TcpIn>, Option<TcpConn>) = if cfg.force_relay {
        (None, None)
    } else {
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
        let (tcp_conn_tx, tcp_conn_rx) = mpsc::channel(64);
        let targets: Vec<([u8; 32], Vec<SocketAddr>)> = r
            .peers
            .iter()
            .filter(|p| own_pub.as_bytes() < &p.pubkey)
            .map(|p| (p.pubkey, p.candidates.clone()))
            .collect();
        tokio::spawn(tcp_direct_manager(
            cfg.listen_port,
            *own_pub.as_bytes(),
            targets,
            tcp_in_tx,
            tcp_conn_tx,
        ));
        (Some(tcp_in_rx), Some(tcp_conn_rx))
    };

    // Routing tables (shard = peer index % N): the readers use these to fan each
    // packet to the worker that owns its peer.
    let index_owner: worker::IndexOwner = Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new()));
    let mut peer_to_wid: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();
    let mut cand_to_wid: std::collections::HashMap<SocketAddr, usize> = std::collections::HashMap::new();
    let mut allowed: Vec<(Vec<String>, [u8; 32], usize)> = Vec::new();
    // Live membership snapshot for the reconcile loop (REVOKE-1): pubkey → (owning
    // worker, candidates, allowed-ips), diffed against fresh config on epoch change.
    let mut known: std::collections::HashMap<[u8; 32], (usize, Vec<SocketAddr>, Vec<String>)> =
        std::collections::HashMap::new();
    // Shared live per-peer status + byte counters, written by workers, read by the
    // local status socket (`fluxpeer show` / wg-UAPI).
    let status_reg = status::registry();
    let mut shards: Vec<Vec<Peer>> = (0..n).map(|_| Vec::new()).collect();
    let mut shard_maps: Vec<std::collections::HashMap<u32, [u8; 32]>> =
        (0..n).map(|_| std::collections::HashMap::new()).collect();

    let now0 = Instant::now();
    for (i, pi) in r.peers.into_iter().enumerate() {
        let wid = i % n;
        let initiator = own_pub.as_bytes() < &pi.pubkey;
        peer_to_wid.insert(pi.pubkey, wid);
        for c in &pi.candidates {
            cand_to_wid.insert(*c, wid);
        }
        known.insert(pi.pubkey, (wid, pi.candidates.clone(), pi.allowed_ips.clone()));
        let stat = status::PeerStat::new(pi.allowed_ips.clone());
        status_reg.write().insert(pi.pubkey, stat.clone());
        allowed.push((pi.allowed_ips, pi.pubkey, wid));
        let mut peer = Peer::fresh(pi.pubkey, pi.candidates, cfg.force_relay, stat);
        if !cfg.force_relay {
            for c in &peer.candidates {
                let _ = udp.send_to(&ping, *c).await;
            }
        }
        if initiator {
            let peer_pub = PublicKey::from(peer.pubkey);
            match peer.raw.init_handshake(own_priv.clone(), peer_pub) {
                Ok(init) => {
                    // Record OUR sender index in the owning shard + the shared owner
                    // table, so the peer's RESP/DATA route back to this worker.
                    if let Some(idx) = le_u32(&init, 4) {
                        shard_maps[wid].insert(idx, peer.pubkey);
                        index_owner.write().insert(idx, wid);
                    }
                    send_to_peer(&udp, &peer, cfg.force_relay, &relay_out, &init).await;
                    peer.init_packet = Some(init);
                    peer.init_sent_at = Some(now0);
                    tracing::info!(dst = ?peer.direct_addr, "sent handshake init (initiator)");
                }
                Err(e) => tracing::error!(error = ?e, "init_handshake failed"),
            }
        }
        shards[wid].push(peer);
    }
    let peers_total: usize = shards.iter().map(Vec::len).sum();
    tracing::info!(peers = peers_total, workers = n, "sessions started");

    // --- data plane: N worker actors (peers sharded by index % N); central
    // readers route each packet to its owner; one writer drains the TUN. ---
    // Behind RwLock so the reconcile loop (REVOKE-1) can add/remove routing entries
    // live; readers take a brief read-lock per packet (like `index_owner`) and drop
    // it before any await.
    let peer_to_wid = Arc::new(parking_lot::RwLock::new(peer_to_wid));
    let cand_to_wid = Arc::new(parking_lot::RwLock::new(cand_to_wid));
    let allowed = Arc::new(parking_lot::RwLock::new(allowed));
    let (tun_out_tx, mut tun_out_rx) = mpsc::channel::<Vec<u8>>(4096);
    let mut wtxs: Vec<mpsc::Sender<worker::WorkerMsg>> = Vec::with_capacity(n);
    let mut wrxs: Vec<mpsc::Receiver<worker::WorkerMsg>> = Vec::with_capacity(n);
    for _ in 0..n {
        let (tx, rx) = mpsc::channel::<worker::WorkerMsg>(1024);
        wtxs.push(tx);
        wrxs.push(rx);
    }

    // TUN writer: sole owner of the framed sink (one fd → writes are serial).
    tokio::spawn(async move {
        while let Some(pkt) = tun_out_rx.recv().await {
            if tun_tx.send(TunPacket::new(pkt)).await.is_err() {
                break;
            }
        }
    });
    // TUN reader: egress IP packet → owning peer/worker by allowed_ips.
    {
        let wtxs = wtxs.clone();
        let allowed = allowed.clone();
        tokio::spawn(async move {
            while let Some(Ok(pkt)) = tun_rx.next().await {
                let bytes = pkt.get_bytes();
                let route = {
                    let a = allowed.read();
                    worker::route_tun(bytes, &a)
                };
                if let Some((pk, wid)) = route
                    && wtxs[wid]
                        .send(worker::WorkerMsg::TunEgress {
                            pk,
                            pkt: bytes.to_vec(),
                        })
                        .await
                        .is_err()
                {
                    break;
                }
            }
        });
    }
    // UDP reader: route each datagram (disco/wg) to its owning worker.
    {
        let udp = udp.clone();
        let wtxs = wtxs.clone();
        let peer_to_wid = peer_to_wid.clone();
        let cand_to_wid = cand_to_wid.clone();
        let index_owner = index_owner.clone();
        let own_priv = own_priv.clone();
        tokio::spawn(async move {
            // Batched receive (recvmmsg): read up to RECV_BATCH datagrams per
            // syscall — the receive-side complement to send GSO.
            let mut batch = gso::RecvBatch::new();
            'outer: loop {
                let count = match batch.recv(&udp).await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                for i in 0..count {
                    let (data, from) = batch.get(i);
                    let wid = {
                        let pw = peer_to_wid.read();
                        let cw = cand_to_wid.read();
                        worker::route_udp(data, from, &pw, &cw, &index_owner, &own_priv, &own_pub)
                    };
                    let Some(wid) = wid else {
                        continue;
                    };
                    let msg = worker::WorkerMsg::UdpIn {
                        from,
                        bytes: data.to_vec(),
                    };
                    if wtxs[wid].send(msg).await.is_err() {
                        break 'outer;
                    }
                }
            }
        });
    }
    // Relay inbound forwarder (route by pubkey / peeked INIT).
    if let Some(mut relay_in) = relay_in {
        let wtxs = wtxs.clone();
        let peer_to_wid = peer_to_wid.clone();
        let own_priv = own_priv.clone();
        tokio::spawn(async move {
            while let Some((src, bytes)) = relay_in.recv().await {
                let wid = {
                    let pw = peer_to_wid.read();
                    worker::route_framed(&bytes, &src, &pw, &own_priv, &own_pub)
                };
                if let Some(wid) = wid
                    && wtxs[wid].send(worker::WorkerMsg::RelayIn { src, bytes }).await.is_err()
                {
                    break;
                }
            }
        });
    }
    // TCP-direct inbound forwarder.
    if let Some(mut tcp_in) = tcp_in {
        let wtxs = wtxs.clone();
        let peer_to_wid = peer_to_wid.clone();
        let own_priv = own_priv.clone();
        tokio::spawn(async move {
            while let Some((src, bytes)) = tcp_in.recv().await {
                let wid = {
                    let pw = peer_to_wid.read();
                    worker::route_framed(&bytes, &src, &pw, &own_priv, &own_pub)
                };
                if let Some(wid) = wid
                    && wtxs[wid].send(worker::WorkerMsg::TcpIn { src, bytes }).await.is_err()
                {
                    break;
                }
            }
        });
    }
    // TCP-direct connection up/down forwarder (route by pubkey).
    if let Some(mut tcp_conn_rx) = tcp_conn_rx {
        let wtxs = wtxs.clone();
        let peer_to_wid = peer_to_wid.clone();
        tokio::spawn(async move {
            while let Some((pk, g, out)) = tcp_conn_rx.recv().await {
                let wid = peer_to_wid.read().get(&pk).copied();
                if let Some(wid) = wid
                    && wtxs[wid]
                        .send(worker::WorkerMsg::TcpConn { pk, conn_gen: g, out })
                        .await
                        .is_err()
                {
                    break;
                }
            }
        });
    }

    // Spawn the N worker actors (each owns its shard's peers + cryptors).
    for (wid, wrx) in wrxs.into_iter().enumerate() {
        let state = worker::WorkerState {
            peers: std::mem::take(&mut shards[wid]),
            index_map: worker::IndexTable::new(std::mem::take(&mut shard_maps[wid]), index_owner.clone(), wid),
            udp: udp.clone(),
            relay_out: relay_out.clone(),
            own_priv: own_priv.clone(),
            own_pub,
            force_relay: cfg.force_relay,
            ping: ping.clone(),
            tun_out: tun_out_tx.clone(),
            status: status_reg.clone(),
        };
        tokio::spawn(state.run(wrx));
    }

    // --- Local status socket: `fluxpeer show` + wg-UAPI (`wg show`). ---
    tokio::spawn(statusd::serve(
        statusd::socket_path(&cfg.tun_name),
        status_reg.clone(),
        hex::encode(own_priv.to_bytes()),
        hex::encode(own_pub.as_bytes()),
        cfg.tun_name.clone(),
        cfg.listen_port,
        r.own_addr,
        cfg.control_server.clone(),
    ));

    // --- Periodic traffic-stats report to the control-server (powers the web's
    // cumulative + realtime traffic view; realtime = the web's Δbytes/Δt). ---
    {
        let reg = status_reg.clone();
        let control_server = cfg.control_server.clone();
        let device_id = cfg.device_id.clone();
        let auth_token = cfg.auth_token.clone().unwrap_or_default();
        tokio::spawn(async move {
            let client = fluxpeer_sdk::Client::with_password(control_server, &auth_token);
            // 3 s cadence so the web's realtime rate (Δbytes/Δt) feels live without
            // hammering the control-server.
            let mut iv = tokio::time::interval(Duration::from_secs(3));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                iv.tick().await;
                let snap = status::snapshot(&reg);
                let rx: u64 = snap.iter().map(|p| p.rx_bytes).sum();
                let tx: u64 = snap.iter().map(|p| p.tx_bytes).sum();
                let peers: Vec<serde_json::Value> = snap
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "public_key": hex::encode(p.pubkey),
                            "rx_bytes": p.rx_bytes,
                            "tx_bytes": p.tx_bytes,
                            "transport": status::transport_name(p.transport),
                            "last_handshake_unix": p.last_handshake_unix,
                        })
                    })
                    .collect();
                let _ = client
                    .report_stats(&device_id, rx as i64, tx as i64, &serde_json::Value::Array(peers))
                    .await;
            }
        });
    }

    // --- REVOKE-1: steady-state membership reconcile. Poll the control-server's
    // device_config; when its config_epoch advances (a device was revoked or a new
    // one enrolled), diff the peer set against `known` and add/remove peers LIVE —
    // routing tables + worker sessions + TUN routes — with no restart. A revoked
    // peer's session is dropped within one poll (~2s), so it can no longer send or
    // receive (fail-closed). Endpoint-only roaming is left to wg/disco; the
    // tcp-direct middle rung is not live-updated (a new peer still gets udp-direct +
    // relay; revoked peers lose their session regardless). ---
    tokio::spawn(
        Reconciler {
            client: crate::control::mk_client(&cfg),
            device_id: cfg.device_id.clone(),
            tun_name: dev_name.clone(), // route ops target the real device (utunN on macOS)
            n,
            own_pub,
            peer_to_wid: peer_to_wid.clone(),
            cand_to_wid: cand_to_wid.clone(),
            allowed: allowed.clone(),
            wtxs: wtxs.clone(),
            ordinal: known.len(),
            known,
            last_epoch: init_epoch,
            exit_state: exit_state.clone(),
            control_host,
            relay_ips,
            exclude_routes: cfg.exclude_routes.clone(),
            dns_override: eff_dns.clone(),
        }
        .run(),
    );

    // The control task IS this loop: broadcast a 1 Hz tick to every worker (drives
    // liveness / keepalive / proactive rekey). Diverges → keeps run() alive.
    let mut retry = tokio::time::interval(Duration::from_secs(1));
    loop {
        retry.tick().await;
        for tx in &wtxs {
            let _ = tx.try_send(worker::WorkerMsg::Tick);
        }
    }
}

pub use config::keygen;
pub use daemon::daemon;
pub use join::join;
pub use show::{list_networks, show};
pub use join::config_dir;

/// Install admin-set DNS servers (the editable `DNS =` wg setting). Writing
/// `/etc/resolv.conf` clobbers system DNS, so it's gated behind `FLUXPEER_MANAGE_DNS=1`
/// (opt-in, like wg-quick's DNS handling); otherwise we just log what was set.
fn apply_dns(servers: &[String], iface: &str) {
    if servers.is_empty() {
        return;
    }
    let manage = std::env::var("FLUXPEER_MANAGE_DNS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !manage {
        tracing::info!(?servers, "admin-set DNS (apply with FLUXPEER_MANAGE_DNS=1)");
        return;
    }
    let body: String = servers.iter().map(|s| format!("nameserver {s}\n")).collect();
    #[cfg(not(windows))]
    {
        let _ = iface;
        match std::fs::write("/etc/resolv.conf", format!("# managed by fluxpeer\n{body}")) {
            Ok(()) => tracing::info!(?servers, "applied DNS to /etc/resolv.conf"),
            Err(e) => tracing::warn!(error = %e, "could not write /etc/resolv.conf"),
        }
    }
    #[cfg(windows)]
    {
        let _ = &body;
        use std::os::windows::process::CommandExt;
        let servers_csv = servers.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",");
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("Set-DnsClientServerAddress -InterfaceAlias '{iface}' -ServerAddresses {servers_csv} -ErrorAction SilentlyContinue")])
            .creation_flags(0x08000000)
            .status();
        tracing::info!(?servers, iface, "applied DNS via Set-DnsClientServerAddress");
    }
}
