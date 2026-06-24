//! fluxpeer relay-server (DERP-style). Ciphertext-only datagram forwarding
//! addressed by Curve25519 pubkey, carried over fluxpeer transports (TCP now,
//! anytls/443 later). The relay never decrypts payloads.
//!
//! - [`proto`] — wire frame codec (`[type][len][body]`).
//! - [`hub`] — transport-independent `pubkey → conn` router with bounded queues.
//! - [`ratelimit`] — per-client token-bucket inbound rate limiting.
//! - [`server`] — the network layer: handshake/auth + accept loop over any stream.

pub mod hub;
pub mod proto;
pub mod ratelimit;
pub mod server;
pub mod stun;

/// Serve the relay-server from the environment (`FLUXPEER_RELAY_ADDR` + optional
/// `_STUN_ADDR`/`_ANYTLS_ADDR`/`_BOND_ADDR`/`_NODE_ID`). Shared by the
/// `relay-server` bin and `fluxpeer relay`.
pub async fn serve_from_env() -> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AllowAll, Config, RelayServer};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    let addr: SocketAddr = std::env::var("FLUXPEER_RELAY_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 3478)));
    let mut cfg = Config::default();
    if let Some(r) = std::env::var("FLUXPEER_RELAY_RATE_PER_SEC")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        cfg.rate_per_sec = r;
    }
    if let Some(b) = std::env::var("FLUXPEER_RELAY_BURST").ok().and_then(|s| s.parse().ok()) {
        cfg.burst = b;
    }
    let server = Arc::new(RelayServer::new(cfg, Arc::new(AllowAll::default())));

    // The relay DOUBLES AS the STUN responder: the control-server advertises a
    // relay's URL as its STUN server by default (see `register_relay`,
    // `stun_url.or(url)`), so the responder must run by default too — else a
    // happy-path self-host advertises a STUN endpoint that nothing answers, NATed
    // peers (notably phones) never learn their reflexive address, and they can't be
    // reached inbound → no stable direct path, permanent relay flap. STUN is UDP and
    // the relay protocol is TCP, so they coexist on the same `addr`. The env var only
    // OVERRIDES the bind addr (e.g. to expose STUN on a different port).
    let stun_addr = std::env::var("FLUXPEER_RELAY_STUN_ADDR")
        .ok()
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .unwrap_or(addr);
    tokio::spawn(async move {
        if let Err(e) = crate::stun::serve_stun(stun_addr).await {
            tracing::error!(error = %e, "STUN responder stopped");
        }
    });
    if let Some(tls_addr) = std::env::var("FLUXPEER_RELAY_ANYTLS_ADDR")
        .ok()
        .and_then(|s| s.parse::<SocketAddr>().ok())
    {
        let node_id = std::env::var("FLUXPEER_RELAY_NODE_ID").unwrap_or_else(|_| "fluxpeer-relay".to_string());
        let s = server.clone();
        tokio::spawn(async move {
            tracing::info!("fluxpeer relay-server AnyTLS (bonded) listening on {tls_addr}");
            let config = fp_transport::Config {
                endpoint: tls_addr.ip(),
                port: tls_addr.port(),
                timeout: std::time::Duration::from_secs(30),
                tls: None,
            };
            if let Err(e) = s.serve_anytls(config, node_id).await {
                tracing::error!(error = %e, "anytls listener stopped");
            }
        });
    }
    if let Some(bond_addr) = std::env::var("FLUXPEER_RELAY_BOND_ADDR")
        .ok()
        .and_then(|s| s.parse::<SocketAddr>().ok())
    {
        let s = server.clone();
        tokio::spawn(async move {
            tracing::info!("fluxpeer relay-server TCP-bond listening on {bond_addr}");
            let config = fp_transport::Config {
                endpoint: bond_addr.ip(),
                port: bond_addr.port(),
                timeout: std::time::Duration::from_secs(30),
                tls: None,
            };
            if let Err(e) = s.serve_bonded(config).await {
                tracing::error!(error = %e, "tcp-bond listener stopped");
            }
        });
    }

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("fluxpeer relay-server (plain TCP) listening on {addr}");
    server.serve(listener).await?;
    Ok(())
}
