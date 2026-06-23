//! fluxpeer control-server — coordination plane.
//!
//! Open, no billing. Owns network/device/invite/peer/route coordination and the
//! `/api/v1` HTTP surface (WS push + HTTPS pull land next; see).

use axum::Extension;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod domain;
pub mod ipam;
pub mod persistence;
pub mod sql_store;
pub mod state;

use sql_store::{SqlStore, SqlStoreError};
use state::{Store, StoreError};

/// Control-plane HTTP API version (see `api-schema/PROTOCOL_VERSIONING.md`).
pub const SERVER_API_VERSION: &str = "v1";

// Data-plane protocol numbers advertised for compatibility checks. These MUST
// match `fp-node-core::protocol` and `api-schema/PROTOCOL_VERSIONING.md`.
const CLIENT_PROTOCOL_VERSION: u32 = 1;
const SERVER_PROTOCOL_VERSION: u32 = 1;
const RELAY_PROTOCOL_VERSION: u32 = 1;
const MIN_SUPPORTED_CLIENT_PROTOCOL_VERSION: u32 = 1;
const MIN_SUPPORTED_SERVER_PROTOCOL_VERSION: u32 = 1;

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct VersionInfo {
    server_api_version: &'static str,
    client_protocol_version: u32,
    server_protocol_version: u32,
    relay_protocol_version: u32,
    min_supported_client_protocol_version: u32,
    min_supported_server_protocol_version: u32,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        server_api_version: SERVER_API_VERSION,
        client_protocol_version: CLIENT_PROTOCOL_VERSION,
        server_protocol_version: SERVER_PROTOCOL_VERSION,
        relay_protocol_version: RELAY_PROTOCOL_VERSION,
        min_supported_client_protocol_version: MIN_SUPPORTED_CLIENT_PROTOCOL_VERSION,
        min_supported_server_protocol_version: MIN_SUPPORTED_SERVER_PROTOCOL_VERSION,
    })
}

fn store_status(e: StoreError) -> StatusCode {
    match e {
        StoreError::NetworkNotFound | StoreError::DeviceNotFound | StoreError::RouteNotFound => StatusCode::NOT_FOUND,
        StoreError::InvalidInvite => StatusCode::FORBIDDEN,
        StoreError::PoolExhausted => StatusCode::CONFLICT,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct CreateNetworkReq {
    name: String,
}

#[derive(Deserialize)]
struct CreateInviteReq {
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    max_uses: Option<u32>,
}

#[derive(Deserialize)]
struct EnrollReq {
    invite_code: String,
    name: String,
    wg_public_key: String,
}

#[derive(Deserialize)]
struct ImportReq {
    #[serde(default)]
    devices: Vec<domain::ImportDevice>,
}

async fn create_network(
    State(store): State<Arc<Store>>,
    Json(req): Json<CreateNetworkReq>,
) -> (StatusCode, Json<domain::Network>) {
    (StatusCode::CREATED, Json(store.create_network(&req.name)))
}

async fn list_networks(State(store): State<Arc<Store>>) -> Json<Vec<domain::Network>> {
    Json(store.list_networks())
}

async fn create_invite(
    State(store): State<Arc<Store>>,
    Path(network_id): Path<String>,
    Json(req): Json<CreateInviteReq>,
) -> Result<(StatusCode, Json<domain::Invite>), StatusCode> {
    store
        .create_invite(&network_id, req.expires_at, req.max_uses)
        .map(|inv| (StatusCode::CREATED, Json(inv)))
        .map_err(store_status)
}

async fn enroll(
    State(store): State<Arc<Store>>,
    Json(req): Json<EnrollReq>,
) -> Result<(StatusCode, Json<domain::Device>), StatusCode> {
    store
        .enroll(&req.invite_code, &req.name, &req.wg_public_key, now_unix())
        .map(|dev| (StatusCode::CREATED, Json(dev)))
        .map_err(store_status)
}

async fn import_devices(
    State(store): State<Arc<Store>>,
    Path(network_id): Path<String>,
    Json(req): Json<ImportReq>,
) -> Result<(StatusCode, Json<domain::ImportResult>), StatusCode> {
    store
        .import_devices(&network_id, &req.devices)
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(store_status)
}

async fn list_devices(
    State(store): State<Arc<Store>>,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<domain::Device>>, StatusCode> {
    store.list_devices(&network_id).map(Json).map_err(store_status)
}

async fn revoke_device(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    store
        .revoke_device(&device_id)
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(store_status)
}

async fn device_config(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
) -> Result<Json<domain::DeviceConfig>, StatusCode> {
    store.device_config(&device_id).map(Json).map_err(store_status)
}

/// Connect params a thin/mobile client needs to reach the mesh via a **gateway
/// peer** — a peer that advertises a reachable `ip:port`. Derived from the
/// device's pulled [`domain::DeviceConfig`]; there is no separate gateway
/// registry. The mobile node merges these into its `ClientStartReq`
/// (node_pubkey/addr/port for the single-peer Noise handshake + routing).
#[derive(Serialize)]
struct GatewayConfig {
    /// Gateway peer's Curve25519 public key (the Noise handshake target).
    node_pubkey: String,
    /// Gateway endpoint, pre-split — the engine parses `node_addr` as an IpAddr.
    node_addr: String,
    node_port: u16,
    transport_protocol: String,
    /// This device's own overlay addresses (the TUN iface addresses).
    #[serde(skip_serializing_if = "Option::is_none")]
    iface_ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iface_ipv6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<i32>,
    dns: Vec<String>,
    /// AllowedIPs to route into the tunnel (the gateway peer's `allowed_ips`).
    allowed_routes: Vec<String>,
    config_epoch: u64,
}

/// Split an `ip:port` (or `[v6]:port`) endpoint into `(host, port)`.
fn parse_endpoint(ep: &str) -> Option<(String, u16)> {
    let ep = ep.trim();
    if let Some(rest) = ep.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host.to_string(), port.parse().ok()?));
    }
    let (host, port) = ep.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.parse().ok()?))
}

/// Pick a gateway from a device's config: the first active peer advertising a
/// usable `ip:port`. Its `allowed_ips` become the client's tunnel routes.
fn select_gateway(cfg: &domain::DeviceConfig) -> Option<GatewayConfig> {
    for peer in &cfg.peers {
        for ep in &peer.endpoints {
            if let Some((node_addr, node_port)) = parse_endpoint(ep) {
                return Some(GatewayConfig {
                    node_pubkey: peer.wg_public_key.clone(),
                    node_addr,
                    node_port,
                    transport_protocol: "udp".to_string(),
                    iface_ipv4: cfg.address_v4.clone(),
                    iface_ipv6: cfg.address_v6.clone(),
                    mtu: cfg.mtu,
                    dns: cfg.dns.clone(),
                    allowed_routes: peer.allowed_ips.clone(),
                    config_epoch: cfg.config_epoch,
                });
            }
        }
    }
    None
}

/// `GET /devices/:id/gateway` — resolve the gateway connect params for a device
/// (404 if no peer in its network advertises a reachable endpoint yet).
async fn device_gateway(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
) -> Result<Json<GatewayConfig>, StatusCode> {
    let cfg = store.device_config(&device_id).map_err(store_status)?;
    select_gateway(&cfg).map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
struct AdvertiseRouteReq {
    prefix: String,
}

async fn advertise_route(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
    Json(req): Json<AdvertiseRouteReq>,
) -> Result<(StatusCode, Json<domain::Route>), StatusCode> {
    store
        .advertise_route(&device_id, &req.prefix)
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(store_status)
}

async fn approve_route(
    State(store): State<Arc<Store>>,
    Path(route_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    store
        .approve_route(&route_id)
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(store_status)
}

#[derive(Deserialize)]
struct SetEndpointsReq {
    #[serde(default)]
    endpoints: Vec<String>,
}

async fn set_endpoints(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
    Json(req): Json<SetEndpointsReq>,
) -> Result<StatusCode, StatusCode> {
    store
        .set_endpoints(&device_id, &req.endpoints)
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(store_status)
}

async fn sql_set_endpoints(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
    Json(req): Json<SetEndpointsReq>,
) -> Result<StatusCode, StatusCode> {
    s.set_endpoints(&device_id, &req.endpoints)
        .await
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(sql_status)
}

#[derive(Deserialize)]
struct RegisterRelayReq {
    region: String,
    url: String,
    #[serde(default)]
    network_id: Option<String>,
    #[serde(default)]
    anytls: bool,
    #[serde(default)]
    stun_url: Option<String>,
}

async fn register_relay(
    State(store): State<Arc<Store>>,
    Json(req): Json<RegisterRelayReq>,
) -> (StatusCode, Json<domain::RelayNode>) {
    (
        StatusCode::CREATED,
        Json(store.register_relay(&req.region, &req.url, req.network_id, req.anytls, req.stun_url)),
    )
}

async fn list_relays(State(store): State<Arc<Store>>, Path(network_id): Path<String>) -> Json<Vec<domain::RelayNode>> {
    Json(store.list_relays(&network_id))
}

async fn resolve_name(
    State(store): State<Arc<Store>>,
    Path((network_id, name)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match store.resolve(&network_id, &name) {
        Some(addr) => Ok(Json(serde_json::json!({ "name": name, "address": addr }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// WebSocket: push the device's full config on connect, then again whenever the
/// network's config epoch changes (real-time push). Client still does an
/// HTTPS pull on reconnect to converge.
async fn watch_device(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let network_id = store.network_id_of_device(&device_id).ok_or(StatusCode::NOT_FOUND)?;
    let rx = store.subscribe(&network_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(ws.on_upgrade(move |socket| watch_loop(socket, store, device_id, rx)))
}

async fn watch_loop(
    mut socket: WebSocket,
    store: Arc<Store>,
    device_id: String,
    mut rx: tokio::sync::watch::Receiver<u64>,
) {
    // Initial snapshot.
    if !send_config(&mut socket, &store, &device_id).await {
        return;
    }
    // Push on every epoch change; stop if the device is revoked or socket drops.
    while rx.changed().await.is_ok() {
        if !send_config(&mut socket, &store, &device_id).await {
            break;
        }
    }
}

/// Serialize + send the device config; returns false if the socket is gone or
/// the device was revoked (caller should stop).
async fn send_config(socket: &mut WebSocket, store: &Arc<Store>, device_id: &str) -> bool {
    match store.device_config(device_id) {
        Ok(cfg) => {
            let txt = serde_json::to_string(&cfg).unwrap_or_default();
            socket.send(Message::Text(txt)).await.is_ok()
        }
        Err(_) => false, // revoked / gone → close
    }
}

// ---- Persistent (SqlStore-backed) variant of the REST API ----

fn sql_status(e: SqlStoreError) -> StatusCode {
    match e {
        SqlStoreError::NetworkNotFound | SqlStoreError::DeviceNotFound | SqlStoreError::RouteNotFound => {
            StatusCode::NOT_FOUND
        }
        SqlStoreError::InvalidInvite => StatusCode::FORBIDDEN,
        SqlStoreError::PoolExhausted => StatusCode::CONFLICT,
        SqlStoreError::BadPool(_) | SqlStoreError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn sql_create_network(
    State(s): State<Arc<SqlStore>>,
    Json(req): Json<CreateNetworkReq>,
) -> Result<(StatusCode, Json<domain::Network>), StatusCode> {
    s.create_network(&req.name)
        .await
        .map(|n| (StatusCode::CREATED, Json(n)))
        .map_err(sql_status)
}

async fn sql_list_networks(State(s): State<Arc<SqlStore>>) -> Result<Json<Vec<domain::Network>>, StatusCode> {
    s.list_networks().await.map(Json).map_err(sql_status)
}

async fn sql_create_invite(
    State(s): State<Arc<SqlStore>>,
    Path(network_id): Path<String>,
    Json(req): Json<CreateInviteReq>,
) -> Result<(StatusCode, Json<domain::Invite>), StatusCode> {
    s.create_invite(&network_id, req.expires_at, req.max_uses)
        .await
        .map(|i| (StatusCode::CREATED, Json(i)))
        .map_err(sql_status)
}

async fn sql_list_invites(
    State(s): State<Arc<SqlStore>>,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<domain::Invite>>, StatusCode> {
    s.list_invites(&network_id).await.map(Json).map_err(sql_status)
}

async fn sql_get_device_settings(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let raw = s.device_settings(&device_id).await.map_err(sql_status)?;
    Ok(Json(serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))))
}

async fn sql_set_device_settings(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<StatusCode, StatusCode> {
    let json = serde_json::to_string(&body).unwrap_or_else(|_| "{}".to_string());
    s.set_device_settings(&device_id, &json)
        .await
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(sql_status)
}

async fn sql_advertise_route(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
    Json(req): Json<AdvertiseRouteReq>,
) -> Result<(StatusCode, Json<domain::Route>), StatusCode> {
    s.advertise_route(&device_id, &req.prefix)
        .await
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(sql_status)
}

async fn sql_list_device_routes(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
) -> Result<Json<Vec<domain::Route>>, StatusCode> {
    s.list_device_routes(&device_id).await.map(Json).map_err(sql_status)
}

async fn sql_approve_route(State(s): State<Arc<SqlStore>>, Path(route_id): Path<String>) -> Result<StatusCode, StatusCode> {
    s.approve_route(&route_id).await.map(|_| StatusCode::NO_CONTENT).map_err(sql_status)
}

async fn sql_delete_route(State(s): State<Arc<SqlStore>>, Path(route_id): Path<String>) -> Result<StatusCode, StatusCode> {
    s.delete_route(&route_id).await.map(|_| StatusCode::NO_CONTENT).map_err(sql_status)
}

async fn sql_enroll(
    State(s): State<Arc<SqlStore>>,
    Json(req): Json<EnrollReq>,
) -> Result<(StatusCode, Json<domain::Device>), StatusCode> {
    s.enroll(&req.invite_code, &req.name, &req.wg_public_key, now_unix())
        .await
        .map(|d| (StatusCode::CREATED, Json(d)))
        .map_err(sql_status)
}

async fn sql_import_devices(
    State(s): State<Arc<SqlStore>>,
    Path(network_id): Path<String>,
    Json(req): Json<ImportReq>,
) -> Result<(StatusCode, Json<domain::ImportResult>), StatusCode> {
    s.import_devices(&network_id, &req.devices)
        .await
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(sql_status)
}

async fn sql_list_devices(
    State(s): State<Arc<SqlStore>>,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<domain::Device>>, StatusCode> {
    s.list_devices(&network_id).await.map(Json).map_err(sql_status)
}

async fn sql_revoke(State(s): State<Arc<SqlStore>>, Path(device_id): Path<String>) -> Result<StatusCode, StatusCode> {
    s.revoke_device(&device_id)
        .await
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(sql_status)
}

#[derive(Deserialize)]
struct RenameDeviceReq {
    name: String,
}

async fn sql_rename_device(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
    Json(req): Json<RenameDeviceReq>,
) -> Result<Json<domain::Device>, StatusCode> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    s.rename_device(&device_id, name).await.map(Json).map_err(sql_status)
}

async fn sql_device_config(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
) -> Result<Json<domain::DeviceConfig>, StatusCode> {
    s.device_config(&device_id).await.map(Json).map_err(sql_status)
}

/// `GET /devices/:id/gateway` (SQL store) — see [`device_gateway`].
async fn sql_device_gateway(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
) -> Result<Json<GatewayConfig>, StatusCode> {
    let cfg = s.device_config(&device_id).await.map_err(sql_status)?;
    select_gateway(&cfg).map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
struct StatsReportReq {
    rx_bytes: i64,
    tx_bytes: i64,
    #[serde(default)]
    peers: serde_json::Value,
}

/// Node reports its cumulative traffic (open endpoint, like /endpoints).
async fn sql_report_stats(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
    Json(req): Json<StatsReportReq>,
) -> Result<StatusCode, StatusCode> {
    let peers_json = serde_json::to_string(&req.peers).unwrap_or_else(|_| "[]".to_string());
    s.report_stats(&device_id, req.rx_bytes, req.tx_bytes, &peers_json, now_unix())
        .await
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(sql_status)
}

/// A device's latest traffic stats (admin). Empty zeros if never reported.
async fn sql_get_device_stats(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let stats = s.device_stats(&device_id).await.map_err(sql_status)?;
    let v = match stats {
        Some((rx, tx, peers, at)) => serde_json::json!({
            "rx_bytes": rx, "tx_bytes": tx, "updated_at": at,
            "peers": serde_json::from_str::<serde_json::Value>(&peers).unwrap_or_else(|_| serde_json::json!([])),
        }),
        None => serde_json::json!({ "rx_bytes": 0, "tx_bytes": 0, "updated_at": 0, "peers": [] }),
    };
    Ok(Json(v))
}

/// Per-device traffic rollup for a network (admin) — for the device table.
async fn sql_network_stats(
    State(s): State<Arc<SqlStore>>,
    Path(network_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let rows = s.network_stats(&network_id).await.map_err(sql_status)?;
    let arr: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, rx, tx, at)| serde_json::json!({ "device_id": id, "rx_bytes": rx, "tx_bytes": tx, "updated_at": at }))
        .collect();
    Ok(Json(serde_json::Value::Array(arr)))
}

async fn sql_register_relay(
    State(s): State<Arc<SqlStore>>,
    Json(req): Json<RegisterRelayReq>,
) -> Result<(StatusCode, Json<domain::RelayNode>), StatusCode> {
    s.register_relay(&req.region, &req.url, req.network_id, req.anytls, req.stun_url)
        .await
        .map(|r| (StatusCode::CREATED, Json(r)))
        .map_err(sql_status)
}

async fn sql_list_relays(
    State(s): State<Arc<SqlStore>>,
    Path(network_id): Path<String>,
) -> Result<Json<Vec<domain::RelayNode>>, StatusCode> {
    s.list_relays(&network_id).await.map(Json).map_err(sql_status)
}

async fn sql_watch_device(
    State(s): State<Arc<SqlStore>>,
    Path(device_id): Path<String>,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    let network_id = s
        .network_of(&device_id)
        .await
        .map_err(sql_status)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let rx = s.subscribe(&network_id);
    Ok(ws.on_upgrade(move |socket| sql_watch_loop(socket, s, device_id, rx)))
}

async fn sql_watch_loop(
    mut socket: WebSocket,
    store: Arc<SqlStore>,
    device_id: String,
    mut rx: tokio::sync::watch::Receiver<u64>,
) {
    if !sql_send_config(&mut socket, &store, &device_id).await {
        return;
    }
    while rx.changed().await.is_ok() {
        if !sql_send_config(&mut socket, &store, &device_id).await {
            break;
        }
    }
}

async fn sql_send_config(socket: &mut WebSocket, store: &Arc<SqlStore>, device_id: &str) -> bool {
    match store.device_config(device_id).await {
        Ok(cfg) => socket
            .send(Message::Text(serde_json::to_string(&cfg).unwrap_or_default()))
            .await
            .is_ok(),
        Err(_) => false,
    }
}

/// Persistent REST + WS API backed by [`SqlStore`] (PostgreSQL in prod).
/// Verified on SQLite.
mod auth;

pub fn sql_router(store: Arc<SqlStore>) -> Router {
    let auth = auth::Auth::new(store.clone());
    // Open: node/client endpoints + health/version + the admin login exchange.
    let open = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/admin/login", post(auth::admin_login))
        .route("/enroll", post(sql_enroll))
        .route("/devices/:id/config", get(sql_device_config))
        .route("/devices/:id/gateway", get(sql_device_gateway))
        .route("/devices/:id/endpoints", post(sql_set_endpoints))
        .route("/devices/:id/stats", post(sql_report_stats))
        .route("/devices/:id/watch", get(sql_watch_device))
        .route("/relays", post(sql_register_relay))
        .route("/networks/:id/relays", get(sql_list_relays))
        .with_state(store.clone());
    // Admin: management routes behind the bearer middleware.
    let admin = Router::new()
        .route("/networks", post(sql_create_network).get(sql_list_networks))
        .route("/networks/:id/invites", post(sql_create_invite).get(sql_list_invites))
        .route("/networks/:id/devices", get(sql_list_devices))
        .route("/networks/:id/devices/import", post(sql_import_devices))
        .route("/networks/:id/stats", get(sql_network_stats))
        .route("/devices/:id", delete(sql_revoke).patch(sql_rename_device))
        .route("/devices/:id/stats", get(sql_get_device_stats))
        .route("/devices/:id/settings", get(sql_get_device_settings).put(sql_set_device_settings))
        .route("/devices/:id/routes", post(sql_advertise_route).get(sql_list_device_routes))
        .route("/routes/:id/approve", post(sql_approve_route))
        .route("/routes/:id", delete(sql_delete_route))
        // account management
        .route("/admin/me", get(auth::admin_me))
        .route("/admin/audit", get(auth::audit_log))
        .route("/admin/password", post(auth::admin_change_password))
        .route("/admin/admins", get(auth::list_admins).post(auth::create_admin))
        .route("/admin/admins/:username", delete(auth::delete_admin))
        .with_state(store)
        .layer(axum::middleware::from_fn(auth::require_admin));
    let api = open.merge(admin).layer(Extension(auth));
    Router::new().nest("/api/v1", api)
}

/// Build the control-server router (versioned under `/api/v1`).
pub fn router(store: Arc<Store>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/networks", post(create_network).get(list_networks))
        .route("/networks/:id/invites", post(create_invite))
        .route("/networks/:id/devices", get(list_devices))
        .route("/networks/:id/devices/import", post(import_devices))
        .route("/enroll", post(enroll))
        .route("/devices/:id", delete(revoke_device))
        .route("/devices/:id/config", get(device_config))
        .route("/devices/:id/gateway", get(device_gateway))
        .route("/devices/:id/endpoints", post(set_endpoints))
        .route("/devices/:id/watch", get(watch_device))
        .route("/devices/:id/routes", post(advertise_route))
        .route("/routes/:id/approve", post(approve_route))
        .route("/networks/:id/resolve/:name", get(resolve_name))
        .route("/relays", post(register_relay))
        .route("/networks/:id/relays", get(list_relays))
        .with_state(store);
    Router::new().nest("/api/v1", api)
}

#[cfg(test)]
mod test {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        router(Arc::new(Store::new()))
    }

    fn get(uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn post(uri: &str, json: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(json.to_string()))
            .unwrap()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = app().oneshot(get("/api/v1/health")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn version_reports_api_v1_and_protocols() {
        let resp = app().oneshot(get("/api/v1/version")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["server_api_version"], "v1");
        assert_eq!(v["client_protocol_version"], 1);
        assert_eq!(v["min_supported_client_protocol_version"], 1);
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let resp = app().oneshot(get("/api/v1/nope")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn enroll_flow_end_to_end() {
        let app = router(Arc::new(Store::new()));

        // 1. create network
        let resp = app
            .clone()
            .oneshot(post("/api/v1/networks", serde_json::json!({"name":"home"})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let net = body_json(resp).await;
        let net_id = net["id"].as_str().unwrap().to_string();

        // 2. create invite
        let resp = app
            .clone()
            .oneshot(post(
                &format!("/api/v1/networks/{net_id}/invites"),
                serde_json::json!({"max_uses": 5}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let code = body_json(resp).await["code"].as_str().unwrap().to_string();

        // 3. enroll a device
        let resp = app
            .clone()
            .oneshot(post(
                "/api/v1/enroll",
                serde_json::json!({"invite_code": code, "name": "laptop", "wg_public_key": "pk-A"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let dev = body_json(resp).await;
        assert_eq!(dev["status"], "active");
        assert!(dev["address_v4"].as_str().unwrap().starts_with("100.72."));

        // 4. list devices
        let resp = app
            .clone()
            .oneshot(get(&format!("/api/v1/networks/{net_id}/devices")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn enroll_with_bad_invite_is_forbidden() {
        let resp = app()
            .oneshot(post(
                "/api/v1/enroll",
                serde_json::json!({"invite_code": "nope", "name": "x", "wg_public_key": "k"}),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// Helper: spin up a network + invite, returning the invite code.
    async fn net_with_invite(app: &Router) -> String {
        let net = body_json(
            app.clone().oneshot(post("/api/v1/networks", serde_json::json!({"name": "home"}))).await.unwrap(),
        )
        .await;
        let net_id = net["id"].as_str().unwrap().to_string();
        body_json(
            app.clone()
                .oneshot(post(&format!("/api/v1/networks/{net_id}/invites"), serde_json::json!({"max_uses": 9})))
                .await
                .unwrap(),
        )
        .await["code"]
            .as_str()
            .unwrap()
            .to_string()
    }

    async fn enroll(app: &Router, code: &str, name: &str, key: &str) -> String {
        body_json(
            app.clone()
                .oneshot(post(
                    "/api/v1/enroll",
                    serde_json::json!({"invite_code": code, "name": name, "wg_public_key": key}),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn gateway_resolves_peer_with_endpoint() {
        let app = app();
        let code = net_with_invite(&app).await;

        // A gateway peer that advertises a public endpoint.
        let gw_id = enroll(&app, &code, "gw", "pk-gw").await;
        let r = app
            .clone()
            .oneshot(post(
                &format!("/api/v1/devices/{gw_id}/endpoints"),
                serde_json::json!({"endpoints": ["203.0.113.7:41820"]}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);

        // The mobile client looks up its gateway.
        let me_id = enroll(&app, &code, "phone", "pk-phone").await;
        let resp = app.clone().oneshot(get(&format!("/api/v1/devices/{me_id}/gateway"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let g = body_json(resp).await;
        assert_eq!(g["node_pubkey"], "pk-gw");
        assert_eq!(g["node_addr"], "203.0.113.7");
        assert_eq!(g["node_port"], 41820);
        assert_eq!(g["transport_protocol"], "udp");
        // The gateway peer's /32 overlay is advertised as a tunnel route.
        assert!(
            g["allowed_routes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().ends_with("/32"))
        );
    }

    #[tokio::test]
    async fn gateway_404_when_no_peer_advertises_endpoint() {
        let app = app();
        let code = net_with_invite(&app).await;
        // A peer exists but reports no endpoint → not reachable as a gateway.
        let _gw = enroll(&app, &code, "gw", "pk-gw").await;
        let me_id = enroll(&app, &code, "phone", "pk-phone").await;
        let resp = app.clone().oneshot(get(&format!("/api/v1/devices/{me_id}/gateway"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

/// Serve the control-server from the environment (`FLUXPEER_CONTROL_ADDR`,
/// `DATABASE_URL`). Shared by the `control-server` bin and `fluxpeer control`.
pub async fn serve_from_env() -> Result<(), Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddr = std::env::var("FLUXPEER_CONTROL_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 8080)));
    let url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "sqlite://fluxpeer.db?mode=rwc".to_string());
    tracing::info!("control-server storage: {}", storage_kind(&url));
    let store = std::sync::Arc::new(crate::sql_store::SqlStore::connect(&url).await?);
    crate::auth::ensure_default_admin(&store).await;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("fluxpeer control-server listening on {addr}");
    axum::serve(listener, crate::sql_router(store)).await?;
    Ok(())
}

fn storage_kind(url: &str) -> &'static str {
    if url.starts_with("postgres") {
        "PostgreSQL (DATABASE_URL)"
    } else if url.starts_with("sqlite") {
        "SQLite (embedded, self-host default)"
    } else {
        "SQL (custom DATABASE_URL)"
    }
}
