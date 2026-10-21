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
use fp_tun::Device; // brings the `.name()` method on the concrete device into scope
use fp_tun::TunPacket;
use futures::{SinkExt, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

mod config;
mod control;
mod daemon;
mod dns;
mod firewall;
mod gso;
mod join;
mod peer;
mod relay;
mod route;
mod show;
mod status;
mod statusd;
mod tcp_direct;
mod util;
mod worker;

use config::Config;
use control::{fetch_relays, resolve_from_control, stun_query};
use peer::{Peer, send_to_peer};
use relay::{RelayIn, RelayOut, RelayTarget, relay_supervisor};
use tcp_direct::{TcpConn, TcpIn, tcp_direct_manager};
use util::{hex32, le_u32, local_ipv4_toward, netmask_v4, url_host};

/// Routing tables the central readers consult. UDP indexes use brief RwLock
/// reads; the TUN prefix table is an immutable snapshot with lock-free reads.
type WidMap = Arc<parking_lot::RwLock<std::collections::HashMap<[u8; 32], usize>>>;
type CandMap = Arc<parking_lot::RwLock<std::collections::HashMap<SocketAddr, usize>>>;
type AllowedMap = Arc<arc_swap::ArcSwap<worker::RouteTable>>;

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
    // Consumer exit selection (AD-2): which exit peer (if any) carries our
    // internet traffic. Static for the process lifetime (a change restarts the
    // iface via the daemon settings path).
    use_exit: Option<String>,
    relay_available: bool,
    // Provider side (AD-1): local override (`exit_node`) / veto (`exit_veto`)
    // over the control-plane's `self_exit`; shared `nat_state` so the SIGTERM
    // handler tears down exactly the NAT we installed.
    provider: ProviderPolicy,
    nat_state: NatState,
    /// Our overlay CIDR (e.g. 100.72.16.0/24) — the NAT source subnet on
    /// Windows/macOS exit-gateway setup.
    own_cidr: String,
    manage_host_routes: bool,
    shutdown: Shutdown,
    desired: Vec<control::PeerInfo>,
    self_exit: bool,
}

use route::{route_del, route_replace};

/// Whether THIS device runs exit forwarding/NAT right now (AD-1 precedence:
/// veto > local force on/off > control-plane `self_exit`).
fn nat_on(override_: Option<bool>, veto: bool, self_exit: bool) -> bool {
    if veto {
        return false;
    }
    match override_ {
        Some(v) => v,
        None => self_exit,
    }
}

/// Shared startup/reconcile wiring for provider policy and host effects.
fn sync_nat(policy: ProviderPolicy, state: &NatState, shutdown: &Shutdown, approved: bool, tun: &str, own_cidr: &str) {
    policy.sync(state, shutdown, approved, route::physical_iface, |enabled, phys| {
        if enabled {
            route::exit_gateway_up(phys, tun, own_cidr);
            tracing::info!(phys, tun, "exit provider: forwarding/NAT UP");
        } else {
            route::exit_gateway_down(phys, tun);
            tracing::info!(phys, tun, "exit provider: forwarding/NAT DOWN");
        }
    });
}

fn set_nat(
    state: &NatState, shutdown: &Shutdown, on: bool,
    discover: impl FnOnce() -> Option<String>, apply: impl FnOnce(bool, &str),
) {
    let stopped = shutdown.lock();
    if *stopped { return; }
    reconcile_nat(&mut state.lock(), on, discover, apply);
}

/// Track only this instance's provider transition. Inject effects so approval,
/// revocation, and local overrides can be tested without privileged networking.
fn reconcile_nat(
    state: &mut Option<String>,
    on: bool,
    discover: impl FnOnce() -> Option<String>,
    apply: impl FnOnce(bool, &str),
) {
    match (on, state.is_some()) {
        (true, false) => {
            if let Some(phys) = discover() {
                apply(true, &phys);
                *state = Some(phys);
            } else {
                tracing::warn!("exit approved but no physical egress interface found");
            }
        }
        (false, true) => {
            if let Some(phys) = state.take() {
                apply(false, &phys);
            }
        }
        _ => {}
    }
}

/// This gate is held through host effects. Shutdown sets the flag under the same
/// gate before teardown, so an in-flight apply completes before cleanup and no
/// later apply can recreate routes or NAT.
type Shutdown = Arc<parking_lot::Mutex<bool>>;

fn shutdown_with(shutdown: &Shutdown, teardown: impl FnOnce()) {
    let mut stopped = shutdown.lock();
    *stopped = true;
    teardown();
}

#[derive(Clone, Copy)]
struct ProviderPolicy {
    enabled: bool,
    force: Option<bool>,
    veto: bool,
}

impl ProviderPolicy {
    fn from_config(cfg: &Config, embedded: bool) -> Self {
        Self { enabled: !embedded, force: cfg.exit_node, veto: cfg.exit_veto }
    }

    fn sync(
        self, state: &NatState, shutdown: &Shutdown, approved: bool,
        discover: impl FnOnce() -> Option<String>, apply: impl FnOnce(bool, &str),
    ) {
        if self.enabled {
            set_nat(state, shutdown, nat_on(self.force, self.veto, approved), discover, apply);
        }
    }
}

/// Retire the old host defaults before publishing a different cryptokey default.
/// The new defaults are installed only after membership/routes have been updated.
fn retire_exit_with<T>(
    state: &parking_lot::Mutex<Option<T>>, shutdown: &Shutdown,
    selected: Option<[u8; 32]>, key: impl Fn(&T) -> [u8; 32], down: impl FnOnce(T),
) {
    let stopped = shutdown.lock();
    if *stopped { return; }
    let mut state = state.lock();
    if state.as_ref().map(key) != selected
        && let Some(old) = state.take()
    {
        down(old);
    }
}

fn selected_exit(peers: &[control::PeerInfo]) -> Option<[u8; 32]> {
    peers.iter().find(|p| p.allowed_ips.iter().any(|c| {
        c.parse::<fluxpeer_sdk::prefix::IpPrefix>().is_ok_and(|p| p.length() == 0 && p.network().is_ipv4())
    })).map(|p| p.pubkey)
}

fn remove_exit(old: ExitTunState) {
    route::exit_down(&old.dev, &old.bypass, old.v6_blocked);
}

/// An unsuccessful apply leaves state empty and is retried even at the same
/// epoch. The overlay membership remains independent of this host-side effect.
fn sync_exit_with<T>(
    state: &parking_lot::Mutex<Option<T>>, shutdown: &Shutdown,
    selected: Option<[u8; 32]>, key: impl Fn(&T) -> [u8; 32],
    up: impl FnOnce() -> std::io::Result<Option<T>>, down: impl FnOnce(T),
) -> std::io::Result<()> {
    let stopped = shutdown.lock();
    if *stopped { return Ok(()); }
    let mut state = state.lock();
    if state.as_ref().map(key) == selected { return Ok(()); }
    if let Some(old) = state.take() { down(old); }
    if selected.is_some() { *state = up()?; }
    Ok(())
}

type KnownPeers = std::collections::HashMap<[u8; 32], (usize, Vec<SocketAddr>, Vec<String>)>;

#[derive(Clone)]
enum PeerChange {
    Remove([u8; 32]),
    Add(control::PeerInfo),
    Endpoints(control::PeerInfo),
    Routes(control::PeerInfo),
}

/// Pure diff with an injectable action sink; endpoint and route changes are
/// independent actions, including when both occur in the same epoch.
fn peer_changes(known: &KnownPeers, desired: &[control::PeerInfo], mut emit: impl FnMut(PeerChange)) {
    for pk in known.keys().filter(|pk| !desired.iter().any(|p| &p.pubkey == *pk)) {
        emit(PeerChange::Remove(*pk));
    }
    for peer in desired {
        if let Some((_, candidates, prefixes)) = known.get(&peer.pubkey) {
            if !same_endpoints(candidates, &peer.candidates) { emit(PeerChange::Endpoints(peer.clone())); }
            if prefixes != &peer.allowed_ips { emit(PeerChange::Routes(peer.clone())); }
        } else { emit(PeerChange::Add(peer.clone())); }
    }
}

/// Two candidate-endpoint sets are equal regardless of order.
fn same_endpoints(a: &[SocketAddr], b: &[SocketAddr]) -> bool {
    a.len() == b.len() && {
        let s: std::collections::HashSet<&SocketAddr> = a.iter().collect();
        b.iter().all(|x| s.contains(x))
    }
}

/// Live full-tunnel teardown state, shared between the Reconciler (which sets it as
/// the selected exit appears/leaves/changes) and the SIGTERM handler (which
/// restores routing/DNS on shutdown).
struct ExitTunState {
    dev: String,
    bypass: Vec<String>,
    /// Whether WE installed the IPv6 egress block (AD-3) — torn down only if so.
    v6_blocked: bool,
    /// The exit peer this state was applied for — a CHANGE of selected exit
    /// re-applies bypass/DNS even though full-tunnel stays up.
    exit_peer: [u8; 32],
}

type ExitState = Arc<parking_lot::Mutex<Option<ExitTunState>>>;

/// Live exit-provider (forwarding/NAT) state: `Some(phys_iface)` while OUR NAT is
/// installed. Shared with the SIGTERM handler so only our own rules come down.
type NatState = Arc<parking_lot::Mutex<Option<String>>>;

/// Apply full-tunnel exit routing for `peers` on `dev`: if a peer routes 0.0.0.0/0
/// (only the SELECTED exit keeps it — see `control::apply_use_exit`), install the
/// split-default + bypass routes (wg carrier, local LAN, control-server, user
/// excludes) + DNS, returning the teardown state; else None.
fn apply_exit(
    peers: &[control::PeerInfo],
    dev: &str,
    control_host: &str,
    relay_ips: &[String],
    exclude_routes: &[String],
    dns_override: &[String],
) -> std::io::Result<Option<ExitTunState>> {
    let Some(ex) = selected_exit(peers).and_then(|pk| peers.iter().find(|p| p.pubkey == pk)) else {
        return Ok(None);
    };
    let (gw, phys) = match (route::default_gateway(), route::physical_iface()) {
        (Some(g), Some(p)) => (g, p),
        _ => {
            tracing::warn!("exit peer present but no physical default gateway/iface — full-tunnel not applied");
            return Err(std::io::Error::other("no physical gateway/interface for full-tunnel"));
        }
    };
    let bypass: Vec<String> = exit_bypass_candidates(control_host, relay_ips, ex, exclude_routes)
        .into_iter().filter(|c| route::needs_bypass(c)).collect();
    let dns = if !dns_override.is_empty() {
        dns_override.first().cloned()
    } else {
        ex.overlay.map(|a| a.to_string())
    };
    let v6_blocked = route::exit_up(dev, &gw, &phys, &bypass, dns.as_deref())?;
    Ok(Some(ExitTunState {
        dev: dev.to_string(),
        bypass,
        v6_blocked,
        exit_peer: ex.pubkey,
    }))
}

/// Physical carrier addresses must escape both IPv4 and IPv6 split defaults.
fn exit_bypass_candidates(control_host: &str, relays: &[String], exit: &control::PeerInfo, excludes: &[String]) -> Vec<String> {
    let mut candidates = vec![control_host.to_string()];
    candidates.extend(relays.iter().cloned());
    candidates.extend(exit.candidates.iter().map(|c| c.ip().to_string()));
    candidates.extend(excludes.iter().cloned());
    candidates.sort();
    candidates.dedup();
    candidates
}

impl Reconciler {
    async fn run(mut self) -> std::io::Result<()> {
        let mut iv = tokio::time::interval(Duration::from_secs(2));
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            iv.tick().await;
            if *self.shutdown.lock() { return Ok(()); }
            if let Some(snap) = control::poll_peers_if_changed(&self.client, &self.device_id, &mut self.last_epoch).await {
                let (_, desired) = control::apply_use_exit(&snap.peers, self.use_exit.as_deref(), self.relay_available);
                retire_exit_with(&self.exit_state, &self.shutdown, selected_exit(&desired), |s| s.exit_peer, remove_exit);
                let mut changes = Vec::new();
                peer_changes(&self.known, &desired, |change| changes.push(change));
                for change in changes {
                    match change {
                        PeerChange::Remove(pk) => self.remove_peer(pk).await,
                        PeerChange::Add(peer) => self.add_peer(peer).await,
                        PeerChange::Endpoints(peer) => self.update_candidates(peer).await,
                        PeerChange::Routes(peer) => self.update_routes(peer),
                    }
                }
                self.desired = desired;
                self.self_exit = snap.self_exit;
            }
            // Retry host effects every tick, including unchanged epochs and
            // transient control-plane errors, using the last successful snapshot.
            self.sync_exit(&self.desired);
            self.sync_nat(self.self_exit);
        }
    }

    /// Re-evaluate full-tunnel: bring exit routing up when the SELECTED exit peer
    /// (the only one keeping 0.0.0.0/0 after `apply_use_exit`) appears, tear it
    /// down when none remains, and re-apply when the selected exit CHANGES (e.g.
    /// a better `auto` candidate shows up) so bypass/DNS follow. Idempotent; the
    /// shared `exit_state` lets the SIGTERM handler restore routing on shutdown.
    fn sync_exit(&self, peers: &[control::PeerInfo]) {
        if !self.manage_host_routes { return; }
        if let Err(error) = sync_exit_with(
            &self.exit_state, &self.shutdown, selected_exit(peers), |s| s.exit_peer,
            || apply_exit(peers, &self.tun_name, &self.control_host, &self.relay_ips, &self.exclude_routes, &self.dns_override),
            remove_exit,
        ) {
            tracing::error!(%error, "full-tunnel apply failed; overlay remains active; retrying next tick");
        }
    }

    /// Re-evaluate the PROVIDER side (AD-1): run local forwarding/NAT exactly
    /// while the control-plane says this device is an approved exit (`self_exit`)
    /// — unless locally forced on (`exit_node: true`) or vetoed (`exit_veto`).
    /// An admin revoking the default route thus tears NAT down on the next
    /// config update; only rules WE installed are removed.
    fn sync_nat(&self, self_exit: bool) {
        sync_nat(self.provider, &self.nat_state, &self.shutdown, self_exit, &self.tun_name, &self.own_cidr);
    }

    fn replace_allowed(&self, peer: [u8; 32], worker: usize, prefixes: &[String]) {
        let next = self.allowed.load().with_peer(peer, worker, prefixes);
        self.allowed.store(Arc::new(next));
    }

    /// An existing peer's AllowedIPs changed (a subnet route was approved/removed) —
    /// swap its routing-table entry + install/remove the TUN routes live. SYNC (no
    /// await across the RwLock guards).
    fn update_routes(&mut self, pi: control::PeerInfo) {
        let Some((wid, cands, old_aips)) = self.known.get(&pi.pubkey).cloned() else {
            return;
        };
        self.replace_allowed(pi.pubkey, wid, &pi.allowed_ips);
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
        self.replace_allowed(pk, wid, &[]);
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
        self.replace_allowed(pi.pubkey, wid, &pi.allowed_ips);
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

/// Owns the OS-injected tun fd until fp-tun adopts it. If `run_with` errors out
/// before adoption (a bind failure, an unreachable control server, …), the guard
/// closes the fd on drop — otherwise it leaks, and on mobile those leaks pile up
/// across every reconnect. Disarmed right before fp-tun takes the fd (fp-tun's own
/// `Fd::Drop` closes it thereafter, so we must NOT double-close).
#[cfg(unix)]
struct InjectedFdGuard(Option<std::os::fd::RawFd>);
#[cfg(unix)]
impl InjectedFdGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}
#[cfg(unix)]
impl Drop for InjectedFdGuard {
    fn drop(&mut self) {
        if let Some(fd) = self.0 {
            use std::os::fd::FromRawFd;
            // SAFETY: we hold sole ownership of this fd until disarm (fp-tun adoption);
            // reclaim it as an OwnedFd so it closes exactly once on drop.
            drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
        }
    }
}

/// Bind `0.0.0.0:port` UDP with SO_REUSEADDR. Reuse lets a rapid stop/start rebind
/// the listen port instead of failing with EADDRINUSE — which, on mobile, would
/// kill the engine *after* `runNode` already reported success and leak the tun fd.
fn bind_reuse_udp(port: u16) -> std::io::Result<UdpSocket> {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

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

    // Register the protect callback process-wide so the relay/tcp-direct/bonded
    // transports (which open their own egress sockets) protect them too, not just
    // the wg UDP socket below. No-op off mobile (protect = None).
    #[cfg(unix)]
    if let Some(p) = &protect {
        fp_transport::set_protect(p.clone());
    }

    // Own the OS-injected tun fd until fp-tun adopts it below, so any early error
    // (bind, control fetch) closes it instead of leaking (see InjectedFdGuard).
    #[cfg(unix)]
    let mut fd_guard = cfg.tun_fd.map(|fd| InjectedFdGuard(Some(fd)));

    // Bind the wg UDP socket FIRST so STUN learns the NAT mapping for this port.
    // SO_REUSEADDR so a rapid stop/start (common on mobile, where the OS keeps the
    // tun/process briefly alive) doesn't hit EADDRINUSE on the listen port and kill
    // the engine. Arc so the data plane can later share one socket across per-core
    // worker tasks (multicore sharding); `&udp` still deref-coerces to `&UdpSocket`.
    let udp = Arc::new(bind_reuse_udp(cfg.listen_port)?);
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

    // AD-2 (consumer exit contract): split-tunnel BY DEFAULT — strip every
    // peer's default prefixes (`0.0.0.0/0`, `::/0`) unless the local `use_exit`
    // setting selects one exit peer, which alone keeps its default prefix in the
    // cryptokey table + OS routes. `relay_available` lets `auto` pick an
    // endpoint-less exit reachable via the relay.
    let relay_available = !relay_targets.is_empty();
    let (selected_key, peers) = control::apply_use_exit(&r.peers, cfg.use_exit.as_deref(), relay_available);
    match selected_key {
        Some(pk) => tracing::info!(exit = %hex::encode(&pk[..4]), "full-tunnel: using selected exit peer (use_exit)"),
        None => tracing::info!("split-tunnel: no exit peer selected"),
    }

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
        tracing::info!(
            os = std::env::consts::OS,
            "node running EMBEDDED (adopting OS-provided tun fd)"
        );
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
    let eff_dns: Vec<String> = if cfg.dns.is_empty() {
        r.dns.clone()
    } else {
        cfg.dns.clone()
    };
    // Disarm BEFORE adoption: fp-tun is about to take ownership of the injected fd
    // and will close it on its own Drop, so the guard must not also close it.
    #[cfg(unix)]
    if let Some(g) = fd_guard.as_mut() {
        g.disarm();
    }
    let dev = fp_tun::create_as_async(&tun_cfg).map_err(std::io::Error::other)?;
    // The actual kernel device name — equals cfg.tun_name on Linux, an auto-assigned
    // utunN on macOS. Routes must target THIS; the logical/status name stays tun_name.
    let dev_name = dev.get_ref().name().to_string();
    tracing::info!(tun = %cfg.tun_name, dev = %dev_name, addr = %r.own_addr, peers = peers.len(), fd = ?injected_fd, "TUN up");

    let control_host = url_host(&cfg.control_server);
    let relay_ips: Vec<String> = relay_targets.iter().map(|rt| rt.addr.ip().to_string()).collect();

    // Host route/DNS/exit setup — ONLY when we own the device. With an injected fd
    // (mobile VpnService) the OS already installed the address, routes (incl. any
    // 0.0.0.0/0 full-tunnel), MTU and DNS; touching them from here would fail or
    // fight the platform. The data plane below is identical — the phone is a full
    // peer (disco/relay/multi-peer/exit-as-a-peer), just without host-side routing.
    let shutdown: Shutdown = Arc::new(parking_lot::Mutex::new(false));
    let exit_state: ExitState = Arc::new(parking_lot::Mutex::new(None));
    if embedded {
        tracing::info!("adopted external tun fd (mobile VpnService); platform owns routes/DNS/exit");
    } else {
        apply_dns(&eff_dns, &dev_name);
        for p in &peers {
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
        // Exit node (full-tunnel): if the SELECTED exit peer routes 0.0.0.0/0, send
        // the default over the tun (split-default) + bypass the wg
        // carrier/LAN/control/relay + DNS = the exit's overlay, per the WireGuard
        // exit-node model. Reconciler re-applies live.
        if let Err(error) = sync_exit_with(
            &exit_state, &shutdown, selected_exit(&peers), |s| s.exit_peer,
            || apply_exit(&peers, &dev_name, &control_host, &relay_ips, &cfg.exclude_routes, &eff_dns), remove_exit,
        ) {
            tracing::error!(%error, "startup full-tunnel apply failed; overlay remains active; retrying next tick");
        }
    }
    // Exit PROVIDER side (AD-1): enable IPv4 forwarding + NAT masquerade so peers'
    // 0.0.0.0/0 traffic actually egresses — while the CONTROL-PLANE says this
    // device is an approved exit (`self_exit`), unless locally forced on
    // (`exit_node: true`, legacy) or vetoed (`exit_veto`). The Reconciler keeps
    // this in sync on every config update (approval revoked → NAT down).
    let own_cidr = {
        // WinNAT masquerades by source subnet, so pass the overlay's network
        // prefix (e.g. 100.72.16.0/24). Linux ignores it (it NATs by egress iface).
        let plen = cfg.prefix_len;
        let mask: u32 = if plen == 0 { 0 } else { u32::MAX << (32 - plen) };
        let net = Ipv4Addr::from(u32::from(r.own_addr) & mask);
        format!("{net}/{plen}")
    };
    let nat_state: NatState = Arc::new(parking_lot::Mutex::new(None));
    let provider = ProviderPolicy::from_config(&cfg, embedded);
    sync_nat(provider, &nat_state, &shutdown, r.self_exit, &dev_name, &own_cidr);

    // Graceful teardown: restore the default route + DNS (client side) and the NAT
    // rule (exit side) on SIGTERM/SIGINT before exiting — the daemon sends SIGTERM,
    // then SIGKILL. Without this a killed full-tunnel node strands the box's routing.
    #[cfg(unix)]
    {
        let es = exit_state.clone();
        let ns = nat_state.clone();
        let tun = dev_name.clone();
        let stopping = shutdown.clone();
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut intr = signal(SignalKind::interrupt())?;
        tokio::spawn(async move {
            tokio::select! { _ = term.recv() => {}, _ = intr.recv() => {} }
            shutdown_with(&stopping, || {
                if let Some(old) = es.lock().take() { remove_exit(old); }
                if let Some(phys) = ns.lock().take() { route::exit_gateway_down(&phys, &tun); }
            });
            std::process::exit(0);
        });
    }
    // Windows has no SIGTERM/SIGINT; hook Ctrl-C so a foreground node still restores
    // routes/DNS (and the exit-side NAT, when it lands) before exiting.
    #[cfg(windows)]
    {
        let es = exit_state.clone();
        let ns = nat_state.clone();
        let tun = dev_name.clone();
        let stopping = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            shutdown_with(&stopping, || {
                if let Some(old) = es.lock().take() { remove_exit(old); }
                if let Some(phys) = ns.lock().take() { route::exit_gateway_down(&phys, &tun); }
            });
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
        .min(peers.len().max(1));

    // --- TCP-direct (middle rung), multi-peer: each peer gets its own direct
    // TCP connection. We dial peers with a larger pubkey (we're the smaller-keyed
    // initiator); smaller-keyed peers dial us and we accept. ---
    let (tcp_in, tcp_conn_rx): (Option<TcpIn>, Option<TcpConn>) = if cfg.force_relay {
        (None, None)
    } else {
        let (tcp_in_tx, tcp_in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(512);
        let (tcp_conn_tx, tcp_conn_rx) = mpsc::channel(64);
        let targets: Vec<([u8; 32], Vec<SocketAddr>)> = peers
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
    let mut allowed = worker::RouteTable::default();
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

    let desired_peers = peers.clone();
    let now0 = Instant::now();
    for (i, pi) in peers.into_iter().enumerate() {
        let wid = i % n;
        let initiator = own_pub.as_bytes() < &pi.pubkey;
        peer_to_wid.insert(pi.pubkey, wid);
        for c in &pi.candidates {
            cand_to_wid.insert(*c, wid);
        }
        known.insert(pi.pubkey, (wid, pi.candidates.clone(), pi.allowed_ips.clone()));
        let stat = status::PeerStat::new(pi.allowed_ips.clone());
        status_reg.write().insert(pi.pubkey, stat.clone());
        allowed = allowed.with_peer(pi.pubkey, wid, &pi.allowed_ips);
        let mut peer = Peer::fresh(pi.pubkey, pi.candidates, cfg.force_relay, stat, &own_priv);
        if !cfg.force_relay {
            let ping = peer.disco_ping(own_pub.as_bytes());
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
    let allowed = Arc::new(arc_swap::ArcSwap::from_pointee(allowed));
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
        let mut written: u64 = 0;
        while let Some(pkt) = tun_out_rx.recv().await {
            let pkt_len = pkt.len();
            match tun_tx.send(TunPacket::new(pkt)).await {
                Ok(()) => {
                    written += 1;
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        written,
                        plaintext_len = pkt_len,
                        "tun fd write failed; writer exiting"
                    );
                    break;
                }
            }
        }
        tracing::warn!(written, "tun writer task exited");
    });
    // TUN reader: egress IP packet → owning peer/worker by allowed_ips.
    {
        let wtxs = wtxs.clone();
        let allowed = allowed.clone();
        tokio::spawn(async move {
            while let Some(Ok(pkt)) = tun_rx.next().await {
                let bytes = pkt.get_bytes();
                let route = {
                    let a = allowed.load();
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
    let mut reconciler = tokio::spawn(
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
            use_exit: cfg.use_exit.clone(),
            relay_available,
            provider,
            nat_state: nat_state.clone(),
            own_cidr: own_cidr.clone(),
            manage_host_routes: injected_fd.is_none(),
            shutdown: shutdown.clone(),
            desired: desired_peers,
            self_exit: r.self_exit,
        }
        .run(),
    );

    // The control task IS this loop: broadcast a 1 Hz tick to every worker (drives
    // liveness / keepalive / proactive rekey). Diverges → keeps run() alive.
    let mut retry = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = retry.tick() => {},
            result = &mut reconciler => {
                shutdown_with(&shutdown, || {
                    if let Some(old) = exit_state.lock().take() { remove_exit(old); }
                    if let Some(phys) = nat_state.lock().take() { route::exit_gateway_down(&phys, &dev_name); }
                });
                return result.map_err(std::io::Error::other)?;
            }
        }
        for tx in &wtxs {
            let _ = tx.try_send(worker::WorkerMsg::Tick);
        }
    }
}

pub use config::keygen;
pub use daemon::{daemon, set_exit, set_use_exit, veto_exit};
pub use join::config_dir;
pub use join::join;
pub use show::{list_networks, show};

pub fn fw_selftest(action: &str, phys: &str, tun: &str) -> std::io::Result<()> {
    let fw = firewall::detect();
    println!("firewall backend: {}", fw.name());
    match action {
        "detect" => {}
        "up" => fw.up(phys, tun),
        "down" => fw.down(phys, tun),
        "killswitch-on" => fw.killswitch_on(phys, tun),
        "killswitch-off" => fw.killswitch_off(phys, tun),
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown fw-selftest action: {other}"),
            ));
        }
    }
    Ok(())
}

pub fn dns_selftest(action: &str, dns: Option<&str>) -> std::io::Result<()> {
    let backend = dns::detect();
    println!("dns backend: {}", backend.name());
    match action {
        "detect" => {}
        "set" => {
            let Some(dns) = dns else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "dns-selftest set requires a DNS server",
                ));
            };
            backend.set(dns);
        }
        "clear" => backend.clear(),
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown dns-selftest action: {other}"),
            ));
        }
    }
    Ok(())
}

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

#[cfg(test)]
mod exit_contract_tests {
    use super::*;

    #[test]
    fn approval_and_revocation_apply_nat_once_and_only_tear_down_owned_state() {
        let mut state = None;
        let mut calls = Vec::new();
        for approved in [false, true, true, false, false, true, false] {
            reconcile_nat(&mut state, nat_on(None, false, approved), || Some("wan0".into()), |on, phys| calls.push((on, phys.to_string())));
        }
        assert_eq!(calls, vec![(true, "wan0".into()), (false, "wan0".into()), (true, "wan0".into()), (false, "wan0".into())]);
        assert!(state.is_none());
    }

    #[test]
    fn local_override_veto_and_missing_egress_preserve_provider_contract() {
        let mut state = None;
        let mut calls = Vec::new();
        for approved in [true, false] {
            reconcile_nat(&mut state, nat_on(Some(true), true, approved), || Some("wan0".into()), |on, _| calls.push(on));
        }
        assert!(calls.is_empty());
        reconcile_nat(&mut state, nat_on(Some(true), false, false), || None, |on, _| calls.push(on));
        assert!(state.is_none());
        reconcile_nat(&mut state, nat_on(Some(true), false, false), || Some("wan1".into()), |on, _| calls.push(on));
        assert_eq!(calls, vec![true]);
        assert_eq!(state.as_deref(), Some("wan1"));
    }
    fn peer(id: u8, endpoint: &str, prefixes: &[&str]) -> control::PeerInfo {
        control::PeerInfo {
            pubkey: [id; 32], candidates: vec![endpoint.parse().unwrap()],
            allowed_ips: prefixes.iter().map(|s| s.to_string()).collect(),
            overlay: None, exit: true,
        }
    }

    fn packet(dst: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    #[test]
    fn failed_exit_apply_keeps_overlay_and_retries_without_a_new_epoch() {
        let state = parking_lot::Mutex::new(None);
        let shutdown = Arc::new(parking_lot::Mutex::new(false));
        let table = worker::RouteTable::default().with_peer([1; 32], 0, &["100.72.16.2/32".into()]);
        let attempts = std::cell::Cell::new(0);
        for tick in 0..3 {
            let result = sync_exit_with(&state, &shutdown, Some([1; 32]), |s| *s, || {
                attempts.set(attempts.get() + 1);
                if tick == 0 { Err(std::io::ErrorKind::AlreadyExists.into()) }
                else { Ok(Some([1; 32])) }
            }, |_| panic!("same exit must not be torn down"));
            assert_eq!(result.is_err(), tick == 0);
            assert_eq!(*state.lock(), if tick == 0 { None } else { Some([1; 32]) });
            assert_eq!(worker::route_tun(&packet([100, 72, 16, 2]), &table), Some(([1; 32], 0)));
        }
        assert_eq!(attempts.get(), 2); // third tick is idempotent
    }

    #[test]
    fn reconcile_applies_endpoints_and_routes_from_the_same_snapshot() {
        let old = peer(1, "192.0.2.1:1000", &["100.72.16.2/32"]);
        let new = peer(1, "192.0.2.2:2000", &["100.72.16.2/32", "10.0.0.0/8"]);
        let known = KnownPeers::from([(old.pubkey, (0, old.candidates.clone(), old.allowed_ips.clone()))]);
        let mut endpoints = old.candidates;
        let mut table = worker::RouteTable::default().with_peer(old.pubkey, 0, &old.allowed_ips);
        let mut actions = Vec::new();
        peer_changes(&known, std::slice::from_ref(&new), |change| match change {
            PeerChange::Endpoints(p) => { endpoints = p.candidates; actions.push("endpoints"); }
            PeerChange::Routes(p) => { table = table.with_peer(p.pubkey, 0, &p.allowed_ips); actions.push("routes"); }
            _ => panic!("existing peer must retain its session"),
        });
        assert_eq!(actions, ["endpoints", "routes"]);
        assert_eq!(endpoints, new.candidates);
        assert_eq!(worker::route_tun(&packet([10, 1, 2, 3]), &table), Some(([1; 32], 0)));
        assert_eq!(worker::route_tun(&packet([100, 72, 16, 2]), &table), Some(([1; 32], 0)));
    }

    #[test]
    fn exit_switch_retires_host_defaults_before_cryptokey_then_installs_new_defaults() {
        let a = peer(1, "192.0.2.1:1000", &["100.72.16.1/32", "0.0.0.0/0"]);
        let b = peer(2, "192.0.2.2:1000", &["100.72.16.2/32", "0.0.0.0/0"]);
        let peers = vec![a, b];
        let (_, old) = control::apply_use_exit(&peers, Some(&hex::encode([1; 32])), false);
        let (_, desired) = control::apply_use_exit(&peers, Some(&hex::encode([2; 32])), false);
        let known = old.iter().map(|p| (p.pubkey, (0, p.candidates.clone(), p.allowed_ips.clone()))).collect();
        let mut table = worker::RouteTable::default();
        for p in &old { table = table.with_peer(p.pubkey, 0, &p.allowed_ips); }
        let state = parking_lot::Mutex::new(Some([1; 32]));
        let shutdown = Arc::new(parking_lot::Mutex::new(false));
        let events = std::cell::RefCell::new(Vec::new());
        retire_exit_with(&state, &shutdown, selected_exit(&desired), |s| *s, |pk| {
            assert_eq!(pk, [1; 32]);
            assert_eq!(worker::route_tun(&packet([8, 8, 8, 8]), &table), Some(([1; 32], 0)));
            events.borrow_mut().push("remove A /1 and bypass");
        });
        peer_changes(&known, &desired, |change| {
            assert!(state.lock().is_none());
            if let PeerChange::Routes(p) = change { table = table.with_peer(p.pubkey, 0, &p.allowed_ips); }
            else { panic!("only cryptokey prefixes should change"); }
        });
        assert_eq!(worker::route_tun(&packet([8, 8, 8, 8]), &table), Some(([2; 32], 0)));
        events.borrow_mut().push("publish B cryptokey default");
        sync_exit_with(&state, &shutdown, selected_exit(&desired), |s| *s, || {
            assert_eq!(worker::route_tun(&packet([8, 8, 8, 8]), &table), Some(([2; 32], 0)));
            events.borrow_mut().push("install B bypass and /1");
            Ok(Some([2; 32]))
        }, |_| panic!("A was already removed")).unwrap();
        assert_eq!(*state.lock(), Some([2; 32]));
        assert_eq!(*events.borrow(), ["remove A /1 and bypass", "publish B cryptokey default", "install B bypass and /1"]);
    }

    #[test]
    fn startup_and_reconcile_provider_wiring_respects_config_and_shutdown() {
        let base = serde_json::json!({"private_key":"00", "device_id":"d", "control_server":"http://example.invalid",
            "listen_port":0, "tun_name":"fp0", "prefix_len":24});
        for (extra, embedded, expected) in [
            (serde_json::json!({}), false, vec![true, false]),
            (serde_json::json!({"exit_node":false}), false, vec![true, false]),
            (serde_json::json!({"exit_node":true}), false, vec![true]),
            (serde_json::json!({"exit_node":true, "exit_veto":true}), false, vec![]),
            (serde_json::json!({}), true, vec![]),
        ] {
            let mut value = base.clone();
            value.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            let cfg: Config = serde_json::from_value(value).unwrap();
            let policy = ProviderPolicy::from_config(&cfg, embedded);
            let state = Arc::new(parking_lot::Mutex::new(None));
            let shutdown = Arc::new(parking_lot::Mutex::new(false));
            let mut calls = Vec::new();
            // The startup config is already approved; subsequent ticks revoke it.
            for approved in [true, true, false, false] {
                policy.sync(&state, &shutdown, approved, || Some("wan0".into()), |on, phys| {
                    assert_eq!(phys, "wan0"); calls.push(on);
                });
            }
            assert_eq!(calls, expected);
            shutdown_with(&shutdown, || { state.lock().take(); });
            policy.sync(&state, &shutdown, true, || panic!("shutdown must skip discovery"), |_, _| panic!("shutdown must skip NAT"));
            assert!(state.lock().is_none());
        }
    }

    #[test]
    fn shutdown_serializes_with_inflight_apply_and_blocks_late_nat_and_exit() {
        let shutdown = Arc::new(parking_lot::Mutex::new(false));
        let state = Arc::new(parking_lot::Mutex::new(None));
        let nat = Arc::new(parking_lot::Mutex::new(None));
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let apply = {
            let (shutdown, state, events) = (shutdown.clone(), state.clone(), events.clone());
            std::thread::spawn(move || sync_exit_with(&state, &shutdown, Some([1; 32]), |s| *s, || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                events.lock().push("apply");
                Ok(Some([1; 32]))
            }, |_| panic!("no old exit")))
        };
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(shutdown.try_lock().is_none()); // gate spans the host effect
        let cleanup = {
            let (shutdown, state, events) = (shutdown.clone(), state.clone(), events.clone());
            std::thread::spawn(move || shutdown_with(&shutdown, || {
                assert_eq!(state.lock().take(), Some([1; 32]));
                events.lock().push("teardown");
            }))
        };
        release_tx.send(()).unwrap();
        apply.join().unwrap().unwrap();
        cleanup.join().unwrap();
        set_nat(&nat, &shutdown, true, || panic!("stopped"), |_, _| panic!("stopped"));
        sync_exit_with(&state, &shutdown, Some([1; 32]), |s| *s, || panic!("stopped"), |_| panic!("stopped")).unwrap();
        assert_eq!(*events.lock(), ["apply", "teardown"]);
        assert!(state.lock().is_none());
        assert!(nat.lock().is_none());
    }

    #[test]
    fn ipv6_carrier_literals_are_preserved_as_bypass_candidates() {
        let exit = peer(1, "[2001:db8::3]:1234", &["0.0.0.0/0"]);
        let host = url_host("https://[2001:db8::1]:443/api");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(exit_bypass_candidates(&host, &["2001:db8::2".into()], &exit, &[]),
            ["2001:db8::1", "2001:db8::2", "2001:db8::3"]);
    }

}
