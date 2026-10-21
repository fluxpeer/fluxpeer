//! Control-server interaction: relay directory pull, STUN, config-pull.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use fluxpeer_sdk::Client;
use fp_disco::Disco;
use tokio::net::UdpSocket;

use crate::config::Config;
use crate::util::{DISCO_MAGIC, disco_dgram, hex32};

/// Build an SDK client that carries this device's auth token as the bearer, so the
/// control-server authorizes its `/devices/:id/*` calls (config pull / endpoints /
/// routes). Empty token → no header (rejected by a token-enforcing server).
pub(crate) fn mk_client(cfg: &Config) -> Client {
    Client::with_password(
        cfg.control_server.clone(),
        cfg.auth_token.as_deref().unwrap_or_default(),
    )
}

/// Preserve HTTP status classification before wrapping the SDK error in io::Error.
/// Authentication, revoked/missing resources and invalid requests need user action;
/// network failures, server failures and rate limits remain retryable.
pub(crate) fn request_error(error: anyhow::Error) -> std::io::Error {
    use std::io::ErrorKind;
    let kind = match error.downcast_ref::<reqwest::Error>().and_then(reqwest::Error::status) {
        Some(status) if matches!(status.as_u16(), 401 | 403) => ErrorKind::PermissionDenied,
        Some(status) if matches!(status.as_u16(), 404 | 410) => ErrorKind::NotFound,
        Some(status) if status.is_client_error() && !matches!(status.as_u16(), 408 | 425 | 429) => ErrorKind::InvalidInput,
        _ => ErrorKind::Other,
    };
    std::io::Error::new(kind, error)
}

pub(crate) fn terminal_control_error(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput)
}

/// Static info about one peer, resolved from the control-server config-pull.
#[derive(Clone)]
pub(crate) struct PeerInfo {
    pub(crate) pubkey: [u8; 32],
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) allowed_ips: Vec<String>,
    /// The peer's overlay address — used as the DNS server when this peer is an
    /// exit node (full-tunnel), per "DNS = the exit node's gateway".
    pub(crate) overlay: Option<std::net::Ipv4Addr>,
    /// This peer is an approved EXIT (AD-1/AD-2): the control-plane flagged it
    /// (`exit: true`), or — against an OLD control-server without the field — it
    /// carries a default prefix in `allowed_ips` (compatibility inference).
    pub(crate) exit: bool,
}

pub(crate) struct Resolved {
    pub(crate) platform: serde_json::Value,
    pub(crate) own_addr: Ipv4Addr,
    pub(crate) peers: Vec<PeerInfo>,
    /// Admin-set wg settings from the control-server (editable in admin-lite).
    pub(crate) mtu: Option<i32>,
    pub(crate) dns: Vec<String>,
    /// THIS device has an approved default route at the control-plane (AD-1):
    /// the local node enables forwarding/NAT while set (unless forced/vetoed).
    /// Absent on old control-servers ⇒ false.
    pub(crate) self_exit: bool,
}

/// The `self_exit` flag of a `device_config` JSON (AD-1). Defaults false on old
/// control-servers that predate the field.
pub(crate) fn parse_self_exit(conf: &serde_json::Value) -> bool {
    conf["self_exit"].as_bool().unwrap_or(false)
}

/// Whether `cidr` is a default route (`0.0.0.0/0` or `::/0`).
pub(crate) fn is_default_prefix(cidr: &str) -> bool {
    cidr.parse::<fluxpeer_sdk::prefix::IpPrefix>().is_ok_and(|p| p.length() == 0)
}

/// Parse the admin-set `mtu` + `dns` settings out of a device_config JSON.
pub(crate) fn parse_settings(conf: &serde_json::Value) -> (Option<i32>, Vec<String>) {
    let mtu = conf["mtu"].as_i64().map(|m| m as i32);
    let dns = conf["dns"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    (mtu, dns)
}

/// A relay learned from the control-server relay directory (A-finish: nodes pull
/// relay/STUN endpoints from coordination instead of pinning them in config).
pub(crate) struct RelayDir {
    pub(crate) url: String,
    pub(crate) anytls: bool,
    pub(crate) node_id: String,
    pub(crate) stun: Option<SocketAddr>,
}

/// Respect explicit transport selection without dialing a directory address
/// using a protocol it does not advertise. Auto keeps all candidates.
pub(crate) fn relay_transport_matches(force: bool, anytls: bool, require_anytls: bool, require_bond: bool) -> bool {
    if !force { return true; }
    if require_anytls { anytls } else if require_bond { !anytls } else { true }
}

/// Fetch the relay directory for this device from the control-server (one GET,
/// before STUN, so we can learn the STUN address from it too). Preserve errors
/// so mobile and forced-relay bootstrap can retry without ending the session.
pub(crate) async fn fetch_relays(cfg: &Config) -> std::io::Result<Vec<RelayDir>> {
    let client = mk_client(cfg);
    let conf = client.device_config(&cfg.device_id).await.map_err(request_error)?;
    Ok(conf["relays"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(RelayDir {
                        url: r["url"].as_str()?.to_string(),
                        anytls: r["anytls"].as_bool().unwrap_or(false),
                        node_id: r["id"].as_str().unwrap_or("fluxpeer-relay").to_string(),
                        stun: r["stun_url"].as_str().and_then(|s| s.parse().ok()),
                    })
                })
                .collect()
        })
        .unwrap_or_default())
}

/// STUN: send a disco Ping to `stun` and return the reflexive (public) `ip:port`
/// it observed us at — our NAT mapping for `udp`, advertised so peers can punch.
pub(crate) async fn stun_query(udp: &UdpSocket, stun: SocketAddr) -> Option<SocketAddr> {
    // Random transaction id, validated on the Pong: binds the reply to THIS query so
    // an off-path attacker who spoofs the STUN server's source can't pre/blind-forge
    // a Pong that poisons our advertised reflexive address (audit finding 8).
    let mut tx_id = [0u8; 12];
    getrandom::getrandom(&mut tx_id).ok()?;
    let ping = disco_dgram(&Disco::Ping {
        tx_id,
        sender: [0u8; 32],
    });
    let mut buf = [0u8; 1500];
    for _ in 0..5 {
        let _ = udp.send_to(&ping, stun).await;
        if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut buf)).await
            && from == stun
            && let Some(body) = buf[..n].strip_prefix(DISCO_MAGIC)
            && let Ok((Disco::Pong { tx_id: echo, observed }, _)) = Disco::decode(body)
            && echo == tx_id
        {
            return Some(observed);
        }
    }
    None
}

/// Parse the peer list out of a control-server `device_config` JSON. Shared by the
/// initial resolve and the steady-state reconcile (REVOKE-1) so both see an
/// identical view of membership/endpoints/allowed-ips.
pub(crate) fn parse_peers(conf: &serde_json::Value) -> Vec<PeerInfo> {
    conf["peers"]
        .as_array()
        .map(|plist| {
            plist
                .iter()
                .filter_map(|p| {
                    let pk = p["wg_public_key"].as_str()?;
                    let candidates = p["endpoints"]
                        .as_array()
                        .map(|e| {
                            e.iter()
                                .filter_map(|x| x.as_str())
                                .filter_map(|s| s.parse().ok())
                                .collect()
                        })
                        .unwrap_or_default();
                    let allowed_ips: Vec<String> = p["allowed_ips"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    // Exit-ness: trust the control-plane's `exit` flag when present;
                    // an OLD control-server predating the field is inferred from a
                    // default prefix in allowed_ips (AD-2 compatibility).
                    let exit = match p["exit"].as_bool() {
                        Some(v) => v,
                        None => allowed_ips.iter().any(|c| is_default_prefix(c)),
                    };
                    Some(PeerInfo {
                        pubkey: hex32(pk),
                        candidates,
                        allowed_ips,
                        overlay: p["address_v4"].as_str().and_then(|s| s.parse().ok()),
                        exit,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The config generation (`config_epoch`) of a `device_config` JSON — bumped by the
/// control-server on any membership/endpoint change, so the node can cheaply detect
/// "something changed" without diffing the whole config every poll.
pub(crate) fn config_epoch(conf: &serde_json::Value) -> u64 {
    conf["config_epoch"].as_u64().unwrap_or(0)
}

/// Report our endpoint(s), then poll config until peers (with endpoints) appear.
/// Returns the resolved peer set plus the `config_epoch` it was pinned at, so the
/// reconcile loop only re-pulls when the epoch actually advances.
pub(crate) async fn resolve_from_control(cfg: &Config, advertise: &[String]) -> std::io::Result<(Resolved, u64)> {
    let client = mk_client(cfg);
    client
        .set_endpoints(&cfg.device_id, advertise)
        .await
        .map_err(request_error)?;
    tracing::info!(?advertise, "reported endpoints to control-server");

    // Only `own_addr` is needed to bring the TUN up — so return the moment the
    // control-server has assigned it, with whatever peers exist right now (even
    // if they haven't reported endpoints yet). Peers and their endpoints are then
    // applied live by the reconcile loop + disco/relay, exactly as in steady
    // state. The old code blocked the interface for up to 8s waiting on peer
    // endpoints, which made every (re)start feel broken; cold-start is now a
    // couple of round-trips.
    let mut last_err: Option<String> = None;
    for attempt in 0..15u32 {
        match client.device_config(&cfg.device_id).await {
            Ok(conf) => {
                if let Some(oa) = conf["address_v4"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok()) {
                    let last_epoch = config_epoch(&conf);
                    let (mtu, dns) = parse_settings(&conf);
                    let self_exit = parse_self_exit(&conf);
                    let peers: Vec<PeerInfo> = parse_peers(&conf);
                    tracing::info!(peer_count = peers.len(), self_exit, "resolved from control-server");
                    return Ok((
                        Resolved {
                            platform: conf.clone(),
                            own_addr: oa,
                            peers,
                            mtu,
                            dns,
                            self_exit,
                        },
                        last_epoch,
                    ));
                }
                // Enrolled but no overlay address yet — retry briefly.
            }
            Err(e) => {
                let error = request_error(e);
                if terminal_control_error(&error) {
                    return Err(error);
                }
                last_err = Some(error.to_string());
            }
        }
        tokio::time::sleep(Duration::from_millis(if attempt < 4 { 200 } else { 500 })).await;
    }
    Err(std::io::Error::other(match last_err {
        Some(e) => format!("control-server gave no own address: {e}"),
        None => "control-server gave no own address".to_string(),
    }))
}

/// A fresh config snapshot from the control-plane: peers + this device's own
/// exit-ness (`self_exit`, AD-1) at the same epoch.
pub(crate) struct Snapshot {
    pub(crate) platform: serde_json::Value,
    pub(crate) epoch: u64,
    pub(crate) peers: Vec<PeerInfo>,
    pub(crate) self_exit: bool,
}

/// Steady-state membership reconcile (REVOKE-1): poll `device_config` and, when the
/// `config_epoch` advances, return the fresh snapshot so the caller can diff it
/// against the live set and add/remove/re-route peers WITHOUT a restart. Returns
/// `None` when nothing changed (or on a transient error — we just retry next tick).
pub(crate) async fn poll_peers_if_changed(
    client: &Client,
    device_id: &str,
    applied_epoch: Option<u64>,
) -> std::io::Result<Option<Snapshot>> {
    let conf = match client.device_config(device_id).await {
        Ok(conf) => conf,
        Err(error) => {
            let error = request_error(error);
            if terminal_control_error(&error) {
                return Err(error);
            }
            tracing::warn!(%error, "control refresh unavailable; retrying next tick");
            return Ok(None);
        }
    };
    let epoch = config_epoch(&conf);
    if Some(epoch) == applied_epoch {
        return Ok(None);
    }
    Ok(Some(Snapshot {
        platform: conf.clone(),
        epoch,
        peers: parse_peers(&conf),
        self_exit: parse_self_exit(&conf),
    }))
}

/// Resolve the local `use_exit` setting against the peer list (AD-2). Returns
/// the SELECTED exit peer's pubkey (whose IPv4 default stays installed) plus
/// the peer list with every OTHER peer's default prefixes stripped — so internet
/// traffic only ever flows to the one chosen exit, and split-tunnel (the
/// default) strips them all. IPv6 defaults are always stripped in this batch.
///
/// `use_exit`: `None`/`"off"` = split; `"auto"` = first exit peer (pubkey
/// order) with a known endpoint or a configured relay;
/// `"<pubkey hex>"` = pin that peer (must exist AND be exit-capable, else error
/// + split — never silently fall back to another exit).
pub(crate) fn apply_use_exit(
    peers: &[PeerInfo],
    use_exit: Option<&str>,
    relay_available: bool,
) -> (Option<[u8; 32]>, Vec<PeerInfo>) {
    let selected = select_exit(peers, use_exit, relay_available);
    let stripped = peers
        .iter()
        .map(|p| {
            let mut p = p.clone();
            // IPv6 exit is unsupported in this batch, including on the selected peer.
            p.allowed_ips.retain(|c| !is_default_prefix(c) || (!c.contains(':') && Some(p.pubkey) == selected));
            p
        })
        .collect();
    (selected, stripped)
}

/// Pick the exit peer per `use_exit` (see [`apply_use_exit`]).
fn select_exit(peers: &[PeerInfo], use_exit: Option<&str>, relay_available: bool) -> Option<[u8; 32]> {
    match use_exit.map(str::trim) {
        None | Some("") | Some("off") => None,
        Some("auto") => {
            // Choose the first reachable exit in pubkey order. A relay makes
            // endpoint-less peers eligible; it does not change the ordering.
            peers.iter()
                .filter(|p| p.exit && (relay_available || !p.candidates.is_empty()))
                .min_by_key(|p| p.pubkey)
                .map(|p| p.pubkey)
        }
        Some(hex_pk) => match parse_pubkey_hex(hex_pk) {
            Some(pk) => match peers.iter().find(|p| p.pubkey == pk && p.exit) {
                Some(p) => Some(p.pubkey),
                None => {
                    tracing::error!(use_exit = hex_pk, "use_exit peer is unknown or not an approved exit; staying split-tunnel");
                    None
                }
            },
            None => {
                tracing::error!(use_exit = hex_pk, "use_exit is not a valid 32-byte hex pubkey; staying split-tunnel");
                None
            }
        },
    }
}

/// Parse a 64-char hex pubkey; `None` on any deviation (no panic on bad input).
fn parse_pubkey_hex(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn http_responses(responses: Vec<(u16, String)>) -> (Config, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let n = stream.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0);
                    request.extend_from_slice(&buf[..n]);
                    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else { continue; };
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let length = headers.lines().find_map(|line| line.strip_prefix("content-length:")?.trim().parse::<usize>().ok()).unwrap_or(0);
                    if request.len() >= end + 4 + length { break; }
                }
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let cfg = serde_json::from_value(serde_json::json!({
            "private_key": "00".repeat(32), "device_id": "test", "control_server": url,
            "listen_port": 0, "tun_name": "fp-test", "prefix_len": 32
        })).unwrap();
        (cfg, server)
    }

    #[tokio::test]
    async fn terminal_http_statuses_exit_directory_and_bootstrap_without_retry() {
        for status in [400, 401, 403, 404, 410, 422] {
            let (cfg, server) = http_responses(vec![(status, "{}".into())]).await;
            let result = tokio::time::timeout(Duration::from_millis(500), crate::mobile::retry_control(true, || fetch_relays(&cfg))).await.unwrap();
            assert!(terminal_control_error(&result.err().unwrap()), "directory HTTP {status}");
            server.await.unwrap();

            // Endpoint publication fails before the first config GET.
            let (cfg, server) = http_responses(vec![(status, "{}".into())]).await;
            let result = tokio::time::timeout(Duration::from_millis(500), crate::mobile::retry_control(true, || resolve_from_control(&cfg, &[]))).await.unwrap();
            assert!(terminal_control_error(&result.err().unwrap()), "endpoints HTTP {status}");
            server.await.unwrap();

            // Endpoint publication succeeds, but the subsequent config GET is terminal.
            let (cfg, server) = http_responses(vec![(200, "{}".into()), (status, "{}".into())]).await;
            let result = tokio::time::timeout(Duration::from_millis(500), crate::mobile::retry_control(true, || resolve_from_control(&cfg, &[]))).await.unwrap();
            assert!(terminal_control_error(&result.err().unwrap()), "config HTTP {status}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn server_failure_and_rate_limit_retry_then_recover() {
        for status in [503, 429] {
            let (cfg, server) = http_responses(vec![(status, "{}".into()), (200, "{\"relays\":[]}".into())]).await;
            let result = tokio::time::timeout(Duration::from_secs(3), crate::mobile::retry_control(true, || fetch_relays(&cfg))).await.unwrap();
            assert!(result.unwrap().is_empty());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn steady_state_revocation_propagates_but_server_failure_keeps_session() {
        for status in [401, 403, 404, 500] {
            let (cfg, server) = http_responses(vec![(status, "{}".into())]).await;
            let result = poll_peers_if_changed(&mk_client(&cfg), &cfg.device_id, Some(1)).await;
            if status == 500 {
                assert!(result.unwrap().is_none());
            } else {
                assert!(terminal_control_error(&result.err().unwrap()));
            }
            server.await.unwrap();
        }
    }

    #[test]
    fn explicit_mobile_transport_filters_incompatible_directory_entries() {
        for advertised in [false, true] {
            assert!(relay_transport_matches(true, advertised, false, false));
            assert!(relay_transport_matches(false, advertised, true, false));
            assert!(relay_transport_matches(false, advertised, false, true));
            assert_eq!(relay_transport_matches(true, advertised, true, false), advertised);
            assert_eq!(relay_transport_matches(true, advertised, false, true), !advertised);
        }
    }

    fn peer(pk: u8, exit: bool, endpoints: &[&str], allowed: &[&str]) -> PeerInfo {
        PeerInfo {
            pubkey: [pk; 32],
            candidates: endpoints.iter().filter_map(|s| s.parse().ok()).collect(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            overlay: None,
            exit,
        }
    }

    fn has_default(p: &PeerInfo) -> bool {
        p.allowed_ips.iter().any(|c| is_default_prefix(c))
    }

    #[test]
    fn split_default_strips_every_default_prefix() {
        let peers = vec![
            peer(1, true, &["1.2.3.4:51820"], &["100.72.16.1/32", "0.0.0.0/0"]),
            peer(2, false, &[], &["100.72.16.2/32"]),
        ];
        // `None` and `"off"` are both split-tunnel.
        for mode in [None, Some("off"), Some("")] {
            let (sel, out) = apply_use_exit(&peers, mode, false);
            assert_eq!(sel, None);
            assert!(out.iter().all(|p| !has_default(p)));
            // Non-default prefixes survive.
            assert!(out[0].allowed_ips.contains(&"100.72.16.1/32".to_string()));
        }
    }

    #[test]
    fn noncanonical_defaults_cannot_hijack_split_or_enable_ipv6_exit() {
        let conf = serde_json::json!({"peers": [
            {"wg_public_key": hex::encode([1; 32]), "allowed_ips": ["100.72.16.1/32", "1.2.3.4/0", "0.0.0.0/00", "2001:db8::1/00"]},
            {"wg_public_key": hex::encode([2; 32]), "allowed_ips": ["100.72.16.2/32", "5.6.7.8/00", "::/000"]}
        ]});
        let peers = parse_peers(&conf);
        assert!(peers.iter().all(|p| p.exit)); // old-control compatibility is semantic too
        let (_, split) = apply_use_exit(&peers, None, false);
        assert!(split.iter().all(|p| !has_default(p)));
        assert_eq!(split[0].allowed_ips, ["100.72.16.1/32"]);
        let (selected, full) = apply_use_exit(&peers, Some(&hex::encode([2; 32])), false);
        assert_eq!(selected, Some([2; 32]));
        assert!(!has_default(&full[0]));
        assert_eq!(full[1].allowed_ips, ["100.72.16.2/32", "5.6.7.8/00"]);
    }

    #[test]
    fn auto_selects_first_exit_with_endpoint_by_pubkey() {
        // Two exits with endpoints: pubkey order decides, not list order.
        let peers = vec![
            peer(9, true, &["1.2.3.9:51820"], &["100.72.16.9/32", "0.0.0.0/0"]),
            peer(3, true, &["1.2.3.3:51820"], &["100.72.16.3/32", "0.0.0.0/0"]),
        ];
        let (sel, out) = apply_use_exit(&peers, Some("auto"), false);
        assert_eq!(sel, Some([3u8; 32]));
        // The selected exit KEEPS its default prefix (return traffic + cryptokey
        // routing); the loser is stripped.
        let winner = out.iter().find(|p| p.pubkey == [3u8; 32]).expect("winner");
        let loser = out.iter().find(|p| p.pubkey == [9u8; 32]).expect("loser");
        assert!(has_default(winner));
        assert!(!has_default(loser));
    }

    #[test]
    fn auto_falls_back_to_relay_reachable_exit() {
        // No endpoints anywhere: without a relay there is no usable exit; with
        // one, the first exit peer is chosen.
        let peers = vec![peer(5, true, &[], &["100.72.16.5/32", "0.0.0.0/0"])];
        assert_eq!(apply_use_exit(&peers, Some("auto"), false).0, None);
        assert_eq!(apply_use_exit(&peers, Some("auto"), true).0, Some([5u8; 32]));
    }

    #[test]
    fn relay_eligibility_preserves_pubkey_order_and_never_installs_v6_default() {
        let peers = vec![
            peer(9, true, &["1.2.3.9:51820"], &["0.0.0.0/0", "::/0"]),
            peer(1, true, &[], &["0.0.0.0/0", "::/0", "fd00::1/128"]),
        ];
        let (selected, out) = apply_use_exit(&peers, Some("auto"), true);
        assert_eq!(selected, Some([1; 32]));
        assert!(out.iter().all(|p| !p.allowed_ips.iter().any(|c| c == "::/0")));
        assert_eq!(out[1].allowed_ips, vec!["0.0.0.0/0", "fd00::1/128"]);
        assert_eq!(apply_use_exit(&peers, Some("auto"), false).0, Some([9; 32]));
    }

    #[test]
    fn pinned_exit_must_exist_and_be_an_exit() {
        let good = hex::encode([7u8; 32]);
        let peers = vec![
            peer(7, true, &["1.2.3.7:51820"], &["100.72.16.7/32", "0.0.0.0/0"]),
            peer(8, false, &[], &["100.72.16.8/32"]),
        ];
        let (sel, out) = apply_use_exit(&peers, Some(&good), false);
        assert_eq!(sel, Some([7u8; 32]));
        assert!(has_default(out.iter().find(|p| p.pubkey == [7u8; 32]).expect("pinned")));

        // Unknown pubkey → error + split (no silent fallback to another exit).
        let (sel, out) = apply_use_exit(&peers, Some(&hex::encode([42u8; 32])), false);
        assert_eq!(sel, None);
        assert!(out.iter().all(|p| !has_default(p)));
        // Known pubkey but NOT an exit → same.
        let (sel, _) = apply_use_exit(&peers, Some(&hex::encode([8u8; 32])), false);
        assert_eq!(sel, None);
        // Garbage → same.
        let (sel, _) = apply_use_exit(&peers, Some("not-hex"), false);
        assert_eq!(sel, None);
    }

    #[test]
    fn old_control_peer_infers_exit_from_default_prefix() {
        // An old control-server sends no `exit` field: inference from allowed_ips.
        let conf = serde_json::json!({
            "peers": [
                {"wg_public_key": hex::encode([1u8; 32]), "allowed_ips": ["100.72.16.1/32", "0.0.0.0/0"]},
                {"wg_public_key": hex::encode([2u8; 32]), "allowed_ips": ["100.72.16.2/32"]}
            ]
        });
        let peers = parse_peers(&conf);
        assert!(peers[0].exit);
        assert!(!peers[1].exit);
        // And a NEW control-server's explicit `exit: false` wins over the prefix
        // (the prefix is still sent for old nodes).
        let conf = serde_json::json!({
            "peers": [
                {"wg_public_key": hex::encode([1u8; 32]), "allowed_ips": ["0.0.0.0/0"], "exit": false}
            ]
        });
        assert!(!parse_peers(&conf)[0].exit);
    }
}
