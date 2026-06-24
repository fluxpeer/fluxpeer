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

/// Static info about one peer, resolved from the control-server config-pull.
#[derive(Clone)]
pub(crate) struct PeerInfo {
    pub(crate) pubkey: [u8; 32],
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) allowed_ips: Vec<String>,
    /// The peer's overlay address — used as the DNS server when this peer is an
    /// exit node (full-tunnel), per "DNS = the exit node's gateway".
    pub(crate) overlay: Option<std::net::Ipv4Addr>,
}

pub(crate) struct Resolved {
    pub(crate) own_addr: Ipv4Addr,
    pub(crate) peers: Vec<PeerInfo>,
    /// Admin-set wg settings from the control-server (editable in admin-lite).
    pub(crate) mtu: Option<i32>,
    pub(crate) dns: Vec<String>,
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

/// Fetch the relay directory for this device from the control-server (one GET,
/// before STUN, so we can learn the STUN address from it too). Empty on any error
/// — the node still runs direct-only.
pub(crate) async fn fetch_relays(cfg: &Config) -> Vec<RelayDir> {
    let client = mk_client(cfg);
    let Ok(conf) = client.device_config(&cfg.device_id).await else {
        return Vec::new();
    };
    conf["relays"]
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
        .unwrap_or_default()
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
                    let allowed_ips = p["allowed_ips"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    Some(PeerInfo {
                        pubkey: hex32(pk),
                        candidates,
                        allowed_ips,
                        overlay: p["address_v4"].as_str().and_then(|s| s.parse().ok()),
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
        .map_err(std::io::Error::other)?;
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
                    let peers: Vec<PeerInfo> = parse_peers(&conf);
                    tracing::info!(peer_count = peers.len(), "resolved from control-server");
                    return Ok((
                        Resolved {
                            own_addr: oa,
                            peers,
                            mtu,
                            dns,
                        },
                        last_epoch,
                    ));
                }
                // Enrolled but no overlay address yet — retry briefly.
            }
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(if attempt < 4 { 200 } else { 500 })).await;
    }
    Err(std::io::Error::other(match last_err {
        Some(e) => format!("control-server gave no own address: {e}"),
        None => "control-server gave no own address".to_string(),
    }))
}

/// Steady-state membership reconcile (REVOKE-1): poll `device_config` and, when the
/// `config_epoch` advances, return the fresh peer set so the caller can diff it
/// against the live set and add/remove/re-route peers WITHOUT a restart. Returns
/// `None` when nothing changed (or on a transient error — we just retry next tick).
pub(crate) async fn poll_peers_if_changed(
    client: &Client,
    device_id: &str,
    last_epoch: &mut u64,
) -> Option<Vec<PeerInfo>> {
    let conf = client.device_config(device_id).await.ok()?;
    let epoch = config_epoch(&conf);
    if epoch == *last_epoch {
        return None;
    }
    *last_epoch = epoch;
    Some(parse_peers(&conf))
}
