//! C / JNI FFI surface for the mobile node (iOS NetworkExtension + Android
//! VpnService drive this in-process).
//!
//! Design + full wiring plan: see the `fluxpeer-mobile-ffi-plan` memory.
//!
//! Flow (two-phase, mobile):
//! 1. `fp_generate_keypair()` — device identity (x25519).
//! 2. (native) enroll the join token at the control `/enroll` → overlay addr.
//! 3. `fp_connect_handshake_only(req_json)` — build transport + Noise
//!    handshake; NO TUN yet.
//! 4. (native) NE `setTunnelNetworkSettings` / VpnService `establish()` → fd.
//! 5. `fp_attach_tun(fd)` — attach the OS-provided fd; data plane goes live.
//! 6. `fp_disconnect()` — teardown.
//!
//! Every function returns a heap `*mut c_char` JSON string the caller must free
//! with `fp_free_string`. Shape: `{"code":200,"type":"OK","result":{...}}` or
//! `{"code":201,"type":"Error","message":"..."}`.
//!
//! IMPORTANT (key difference — mobile vs desktop): this path NEVER creates a TUN,
//! configures routes, sets DNS, or spawns a process. The OS NE/VpnService owns
//! the TUN fd + includedRoutes/excludedRoutes + dnsSettings; the dispatcher only
//! encrypts/forwards packets. (Desktop's `node/src/route.rs` etc. are unused here.)

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;

use serde_json::{Value, json};

use crate::Dispatcher;
use crate::operator::{AssignInterfaceReq, ClientStartReq};

/// Android JNI shims (`Java_dev_fluxpeer_fluxpeer_FluxpeerNative_*`). They reuse
/// the `*_impl` cores below; only string/fd marshaling differs from the C ABI.
#[cfg(target_os = "android")]
mod android;

// ---- return helpers -------------------------------------------------------
//
// The lifecycle logic lives in `*_impl` fns that return a `serde_json::Value`
// envelope. The C ABI (`fp_*`) renders it to a heap `*mut c_char`; the Android
// JNI shims (`ffi::android`) render it to a `jstring`. Single source of truth.

fn ok_val(result: Value) -> Value {
    json!({ "code": 200, "type": "OK", "message": "", "result": result })
}

fn err_val(message: impl std::fmt::Display) -> Value {
    json!({ "code": 201, "type": "Error", "message": message.to_string() })
}

fn into_cstr(v: Value) -> *mut c_char {
    CString::new(v.to_string())
        .unwrap_or_else(|_| CString::new("{}").unwrap())
        .into_raw()
}

fn err(message: impl std::fmt::Display) -> *mut c_char {
    into_cstr(err_val(message))
}

fn cstr_to_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_owned)
}

/// Free a string previously returned by any `fp_*` function.
///
/// # Safety
/// `p` must be a pointer returned by this library (or null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_free_string(p: *mut c_char) {
    if !p.is_null() {
        drop(unsafe { CString::from_raw(p) });
    }
}

// ---- crypto ---------------------------------------------------------------

/// Core: generate a fresh x25519 device keypair as an OK envelope.
fn keypair_val() -> Value {
    let sk = fp_crypto::x25519::StaticSecret::random_from_rng(rand_core::OsRng);
    let pk = fp_crypto::x25519::PublicKey::from(&sk);
    ok_val(json!({
        "private_key": hex::encode(sk.to_bytes()),
        "public_key": hex::encode(pk.to_bytes()),
    }))
}

/// Generate a fresh x25519 device keypair.
/// Returns `{"private_key":"<64hex>","public_key":"<64hex>"}`.
#[unsafe(no_mangle)]
pub extern "C" fn fp_generate_keypair() -> *mut c_char {
    into_cstr(keypair_val())
}

// ---- engine globals (single in-process tunnel = one mobile session) -------

/// Long-lived multi-thread runtime. It drives the dispatcher event loop (the
/// `Dispatcher::run()` join future is spawned here) AND backs the `block_on`
/// for each FFI operator call — those calls arrive on native threads (never a
/// runtime worker) so `block_on` is legal. Every internal `tokio::task::spawn`
/// inside the dispatcher (transport reader, iface handler) lands on this rt.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();

/// Iface params captured at `fp_connect_handshake_only` time and consumed by
/// `fp_attach_tun(fd)` — the OS only hands us the fd after the handshake proves
/// the node reachable (iOS NE `setTunnelNetworkSettings`, Android
/// `VpnService.Builder.establish()`).
struct PendingIface {
    name: String,
    num: u16,
    ipv4: String,
    ipv6: Option<String>,
}

static PENDING_IFACE: parking_lot::Mutex<Option<PendingIface>> = parking_lot::Mutex::new(None);

/// Keepalive task handle. Without a periodic heartbeat the UDP NAT mapping at
/// the gateway expires when the phone is idle (screen off / app backgrounded),
/// silently dropping the tunnel (QA F8). The heartbeat keeps the mapping + Noise
/// session alive; it runs on the engine runtime inside the foreground
/// VpnService process, so it ticks even under lock screen.
static HEARTBEAT: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>> = parking_lot::Mutex::new(None);

/// 25s — WireGuard-style persistent-keepalive cadence; comfortably under the
/// ~30–60s UDP NAT timeout common on mobile carriers.
const HEARTBEAT_SECS: u64 = 25;

/// (Re)spawn the heartbeat loop on the engine runtime, aborting any prior one.
fn spawn_heartbeat(rt: &'static tokio::runtime::Runtime, disp: &'static Dispatcher) {
    let disp = disp.clone();
    let handle = rt.spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(HEARTBEAT_SECS));
        tick.tick().await; // consume the immediate first tick
        loop {
            tick.tick().await;
            if let Err(e) = disp.heartbeat("ping".to_string()).await {
                tracing::error!("[ffi] heartbeat failed, stopping keepalive: {e:?}");
                break;
            }
        }
    });
    if let Some(prev) = HEARTBEAT.lock().replace(handle) {
        prev.abort();
    }
}

fn stop_heartbeat() {
    if let Some(h) = HEARTBEAT.lock().take() {
        h.abort();
    }
}

/// Lock the pending-iface slot. `parking_lot::Mutex` does not poison, so no
/// recovery dance — matches the zero-panic bottom line.
fn pending() -> parking_lot::MutexGuard<'static, Option<PendingIface>> {
    PENDING_IFACE.lock()
}

fn runtime() -> Option<&'static tokio::runtime::Runtime> {
    if let Some(rt) = RUNTIME.get() {
        return Some(rt);
    }
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("fluxpeer-node")
        .build()
    {
        Ok(rt) => {
            // A racing thread may win the `set`; then ours is dropped (it has
            // nothing spawned on it, so Drop returns immediately).
            let _ = RUNTIME.set(rt);
            RUNTIME.get()
        }
        Err(e) => {
            tracing::error!("[ffi] tokio runtime build error: {e}");
            None
        }
    }
}

/// Resolve the shared runtime + dispatcher, spawning the dispatcher event loop
/// exactly once (`get_or_init` guarantees single execution under contention).
fn engine() -> Option<(&'static tokio::runtime::Runtime, &'static Dispatcher)> {
    let rt = runtime()?;
    let disp = DISPATCHER.get_or_init(|| {
        let (disp, join) = Dispatcher::run();
        rt.spawn(join);
        disp
    });
    Some((rt, disp))
}

// ---- C-callback bridge ----------------------------------------------------
//
// `fp_node_core::TransportCallback = extern "C" fn(*const c_char, *const c_char)`.
// On transport teardown the dispatcher invokes the closed callback with two
// heap CStrings (built via `into_raw`) that the callee OWNS and must free.
// Native (Swift/Kotlin) passes real callbacks to learn about teardown; when it
// passes NULL we install this default, which just frees the strings (no leak).
extern "C" fn drop_strings_callback(data: *const c_char, error_message: *const c_char) {
    unsafe {
        if !data.is_null() {
            drop(CString::from_raw(data as *mut c_char));
        }
        if !error_message.is_null() {
            drop(CString::from_raw(error_message as *mut c_char));
        }
    }
}

// ---- start request (deserializable mirror of ClientStartReq) --------------
//
// `ClientStartReq` only derives `Serialize`, and its `fd`/callbacks are
// `#[serde(skip)]` (a non-Option `extern "C" fn` has no Default), so JSON
// cannot build it directly. Parse this mirror, then assemble `ClientStartReq`
// with the callbacks supplied through the FFI boundary.
#[derive(serde::Deserialize)]
struct StartReqJson {
    client_prikey: String,
    node_pubkey: String,
    node_addr: String,
    node_port: u16,
    #[serde(default = "default_transport")]
    transport_protocol: String,
    #[serde(default = "default_crypto")]
    crypto_protocol: String,
    iface_ipv4: String,
    #[serde(default)]
    iface_ipv6: Option<String>,
    #[serde(default)]
    tls: Option<String>,
    /// Node GUID — derives the AnyTLS password when transport is "anytls".
    #[serde(default)]
    node_id: String,
    /// Bonded TCP connection count (1–8) when transport is "tcp-bond".
    #[serde(default)]
    bond_connections: Option<usize>,
}

fn default_transport() -> String {
    "udp".to_string()
}

fn default_crypto() -> String {
    "noise".to_string()
}

/// Some transports read process-global config (set before connect). Apply it
/// from the request before registering the connector.
fn apply_transport_config(req: &StartReqJson) {
    match req.transport_protocol.as_str() {
        "anytls" if !req.node_id.is_empty() => {
            fp_transport_anytls::set_anytls_config(fp_transport_anytls::AnytlsConfig::with_node_id(&req.node_id));
        }
        "tcp-bond" => {
            let mut cfg = fp_transport_tcp_bond::TcpBondConfig::default();
            if let Some(n) = req.bond_connections {
                cfg.bond_connections = n;
            }
            fp_transport_tcp_bond::set_tcp_bond_config(cfg);
        }
        _ => {}
    }
}

fn register_transport(rt: &tokio::runtime::Runtime, disp: &Dispatcher, proto: &str) -> Result<(), String> {
    let connector = match proto {
        "udp" => crate::RawConnector::new::<fp_transport_udp::Connector>(),
        "tcp" => crate::RawConnector::new::<fp_transport_tcp::Connector>(),
        "tcp-bond" => crate::RawConnector::new::<fp_transport_tcp_bond::TcpBondConnector>(),
        "anytls" => crate::RawConnector::new::<fp_transport_anytls::AnytlsConnector>(),
        other => return Err(format!("unsupported transport_protocol: {other}")),
    };
    rt.block_on(disp.set_connector(proto.to_string(), connector))
        .map_err(|e| format!("set_connector failed: {e}"))?;
    Ok(())
}

fn register_crypto(rt: &tokio::runtime::Runtime, disp: &Dispatcher, proto: &str) -> Result<(), String> {
    let cryptor = match proto {
        "noise" => crate::RawCryptor::new::<fp_crypto_noise::Cryptor>(),
        other => return Err(format!("unsupported crypto_protocol: {other}")),
    };
    rt.block_on(disp.set_cryptor(proto.to_string(), cryptor))
        .map_err(|e| format!("set_cryptor failed: {e}"))?;
    Ok(())
}

// ---- tunnel lifecycle -----------------------------------------------------

/// Phase 1: build the transport + run the Noise handshake. No TUN is attached
/// yet — the OS produces the fd only after this proves the node reachable.
///
/// `req_json` = a JSON object with `client_prikey`, `node_pubkey`, `node_addr`,
/// `node_port`, `transport_protocol` (default "udp"), `crypto_protocol`
/// (default "noise"), `iface_ipv4`, optional `iface_ipv6`/`tls`/`node_id`/
/// `bond_connections`. `on_connected`/`on_closed` are nullable C callbacks
/// (`extern "C" fn(*const c_char, *const c_char)`); pass NULL to opt out.
///
/// # Safety
/// `req_json` must be a valid NUL-terminated UTF-8 C string (or null). The two
/// callbacks, if non-null, must remain valid for the lifetime of the session.
type Callback = extern "C" fn(data: *const c_char, error_message: *const c_char);

/// Core handshake logic, shared by the C ABI and the Android JNI shim.
fn connect_handshake_only_impl(raw: &str, on_connected: Option<Callback>, on_closed: Option<Callback>) -> Value {
    let parsed: StartReqJson = match serde_json::from_str(raw) {
        Ok(p) => p,
        Err(e) => return err_val(format!("req_json parse error: {e}")),
    };

    apply_transport_config(&parsed);

    let Some((rt, disp)) = engine() else {
        return err_val("engine unavailable: tokio runtime build failed");
    };

    if let Err(e) = register_transport(rt, disp, &parsed.transport_protocol) {
        return err_val(e);
    }
    if let Err(e) = register_crypto(rt, disp, &parsed.crypto_protocol) {
        return err_val(e);
    }

    // Stash iface params for the follow-up attach. The desktop path ("utun"/100)
    // — `assign_iface` adopts our external fd, so the name/num only label the
    // logical iface, never create a device.
    *pending() = Some(PendingIface {
        name: "utun".to_string(),
        num: 100,
        ipv4: parsed.iface_ipv4.clone(),
        ipv6: parsed.iface_ipv6.clone(),
    });

    let req = ClientStartReq {
        client_prikey: parsed.client_prikey,
        node_pubkey: parsed.node_pubkey,
        node_addr: parsed.node_addr,
        node_port: parsed.node_port,
        tls: parsed.tls,
        transport_protocol: parsed.transport_protocol,
        crypto_protocol: parsed.crypto_protocol,
        iface_ipv4: parsed.iface_ipv4,
        iface_ipv6: parsed.iface_ipv6,
        timeout: None,
        #[cfg(target_os = "windows")]
        path: None,
        fd: None,
        on_connected_callback: on_connected,
        on_closed_callback: on_closed.unwrap_or(drop_strings_callback),
    };

    match rt.block_on(disp.handshake_only(req)) {
        Ok(resp) => ok_val(resp.unwrap_or(Value::Null)),
        Err(e) => {
            pending().take();
            err_val(format!("handshake_only failed: {e}"))
        }
    }
}

/// Phase 1: build the transport + run the Noise handshake. No TUN is attached
/// yet — the OS produces the fd only after this proves the node reachable.
///
/// `req_json` = a JSON object with `client_prikey`, `node_pubkey`, `node_addr`,
/// `node_port`, `transport_protocol` (default "udp"), `crypto_protocol`
/// (default "noise"), `iface_ipv4`, optional `iface_ipv6`/`tls`/`node_id`/
/// `bond_connections`. `on_connected`/`on_closed` are nullable C callbacks
/// (`extern "C" fn(*const c_char, *const c_char)`); pass NULL to opt out.
///
/// # Safety
/// `req_json` must be a valid NUL-terminated UTF-8 C string (or null). The two
/// callbacks, if non-null, must remain valid for the lifetime of the session.
#[unsafe(no_mangle)]
pub extern "C" fn fp_connect_handshake_only(
    req_json: *const c_char,
    // Spelled as the inline fn-pointer type (not the `TransportCallback` alias)
    // so cbindgen sees the niche and emits a nullable C function pointer rather
    // than an opaque `struct Option_TransportCallback`. Same type either way.
    on_connected: Option<extern "C" fn(data: *const c_char, error_message: *const c_char)>,
    on_closed: Option<extern "C" fn(data: *const c_char, error_message: *const c_char)>,
) -> *mut c_char {
    let Some(raw) = cstr_to_string(req_json) else {
        return err("invalid req_json: null or non-utf8 pointer");
    };
    into_cstr(connect_handshake_only_impl(&raw, on_connected, on_closed))
}

/// Phase 2: attach the OS-provided TUN fd to the handshaken session and bring
/// the data plane live. Must follow a successful `fp_connect_handshake_only`.
///
/// # Safety
/// `fd` must be an open TUN file descriptor owned by the OS tunnel provider
/// (iOS `packetFlow` utun, Android `ParcelFileDescriptor`). The dispatcher
/// adopts it; routes/DNS must already be configured by the native layer.
/// Core attach logic, shared by the C ABI and the Android JNI shim.
fn attach_tun_impl(fd: i32) -> Value {
    let Some(iface) = pending().take() else {
        return err_val("attach_tun called before fp_connect_handshake_only (no pending iface)");
    };
    let Some((rt, disp)) = engine() else {
        return err_val("engine unavailable: tokio runtime build failed");
    };

    let req = AssignInterfaceReq {
        name: iface.name,
        num: iface.num,
        ipv4: iface.ipv4,
        ipv6: iface.ipv6,
        fd: Some(fd),
        #[cfg(target_os = "windows")]
        path: None,
    };

    match rt.block_on(disp.attach_iface(req)) {
        Ok(resp) => {
            spawn_heartbeat(rt, disp); // keepalive once the data plane is live
            ok_val(resp.unwrap_or(Value::Null))
        }
        Err(e) => err_val(format!("attach_iface failed: {e}")),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fp_attach_tun(fd: i32) -> *mut c_char {
    into_cstr(attach_tun_impl(fd))
}

/// Core teardown logic, shared by the C ABI and the Android JNI shim.
fn disconnect_impl() -> Value {
    pending().take();
    stop_heartbeat();
    let Some((rt, disp)) = engine() else {
        return err_val("engine unavailable: tokio runtime build failed");
    };
    match rt.block_on(disp.stop()) {
        Ok(resp) => ok_val(resp.unwrap_or(Value::Null)),
        Err(e) => err_val(format!("disconnect failed: {e}")),
    }
}

/// Tear down the tunnel (closes transport, drops iface + cryptor). Idempotent.
#[unsafe(no_mangle)]
pub extern "C" fn fp_disconnect() -> *mut c_char {
    into_cstr(disconnect_impl())
}

// ---- enrollment (optional; `enroll` feature, on by default) ---------------
//
// One-command onboarding for the mobile app: decode a join token, POST the
// control-server `/api/v1/enroll`, return the allocated overlay identity. The
// app pairs this with `fp_generate_keypair` (it supplies `wg_private_key`, which
// the SDK uses to prove possession and derive the public half) and later builds
// the `ClientStartReq` for connect.
//
// HTTP lives here (not native URLSession/OkHttp) because enroll is the one REST
// call and the mobile design keeps it FFI-built-in; the SDK's reqwest is
// rustls-only, so it cross-compiles to iOS/Android cleanly. Compile it out with
// `--no-default-features` for a pure data-plane library.

/// Decode `fp://join/<base64url(JSON)>` (or a bare base64url blob) into
/// `(ctrl, code)`. JSON shape `{"ctrl":"<url>","code":"<invite>"}` — the same
/// string admin-lite renders as a copyable code + QR. (Mirrors node/join.rs.)
#[cfg(feature = "enroll")]
fn decode_join_token(token: &str) -> Result<(String, String), String> {
    use base64::Engine as _;
    let blob = token.trim().strip_prefix("fp://join/").unwrap_or_else(|| token.trim());
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(blob.trim_end_matches('='))
        .map_err(|e| format!("invalid join token (base64): {e}"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid join token (json): {e}"))?;
    let ctrl = v["ctrl"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("join token missing \"ctrl\"")?
        .trim_end_matches('/')
        .to_string();
    let code = v["code"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("join token missing \"code\"")?
        .to_string();
    Ok((ctrl, code))
}

/// Request shape for `fp_enroll`: supply either `token` (a `fp://join/...`
/// string) or an explicit `ctrl` + `code` pair, plus the device `name` and
/// `wg_private_key` (hex, from `fp_generate_keypair`). The private key is needed for
/// the enroll proof-of-possession (audit #11) — the public half + the ECDH proof are
/// derived inside the SDK and the private key never leaves this process. The legacy
/// `wg_public_key` field is accepted but ignored (it's derived from the private key).
#[cfg(feature = "enroll")]
#[derive(serde::Deserialize)]
struct EnrollReqJson {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    ctrl: Option<String>,
    #[serde(default)]
    code: Option<String>,
    name: String,
    wg_private_key: String,
    #[serde(default)]
    #[allow(dead_code)]
    wg_public_key: Option<String>,
}

/// Core enroll logic, shared by the C ABI and the Android JNI shim.
#[cfg(feature = "enroll")]
fn enroll_impl(raw: &str) -> Value {
    let parsed: EnrollReqJson = match serde_json::from_str(raw) {
        Ok(p) => p,
        Err(e) => return err_val(format!("req_json parse error: {e}")),
    };

    let (ctrl, code) = match (parsed.token.as_deref(), parsed.ctrl.as_deref(), parsed.code.as_deref()) {
        (Some(token), _, _) if !token.is_empty() => match decode_join_token(token) {
            Ok(pair) => pair,
            Err(e) => return err_val(e),
        },
        (_, Some(ctrl), Some(code)) if !ctrl.is_empty() && !code.is_empty() => {
            (ctrl.trim_end_matches('/').to_string(), code.to_string())
        }
        _ => return err_val("enroll requires either \"token\" or both \"ctrl\" and \"code\""),
    };

    let Some(rt) = runtime() else {
        return err_val("engine unavailable: tokio runtime build failed");
    };

    // `Client::new` reads FLUXPEER_ADMIN_PASSWORD for admin bearer; unset on
    // mobile, which is correct — `/enroll` is an open (invite-gated) endpoint.
    let client = fluxpeer_sdk::Client::new(ctrl.clone());
    match rt.block_on(client.enroll(&code, &parsed.name, &parsed.wg_private_key)) {
        Ok(mut dev) => {
            if let Some(obj) = dev.as_object_mut() {
                obj.insert("control_server".to_string(), Value::String(ctrl));
            }
            ok_val(dev)
        }
        Err(e) => err_val(format!("enroll failed: {e:#}")),
    }
}

/// Enroll this device against a control-server and return its overlay identity.
///
/// `req_json` = `{"token":"fp://join/<b64>","name":"...","wg_private_key":"<hex>"}`
/// (or `{"ctrl":"...","code":"...",...}` instead of `token`). On success the
/// `result` is the created device — `{id, network_id, name, wg_public_key,
/// address_v4, address_v6, status}` — plus `control_server` (the resolved ctrl
/// URL the app persists for later connects).
///
/// # Safety
/// `req_json` must be a valid NUL-terminated UTF-8 C string (or null).
#[cfg(feature = "enroll")]
#[unsafe(no_mangle)]
pub extern "C" fn fp_enroll(req_json: *const c_char) -> *mut c_char {
    let Some(raw) = cstr_to_string(req_json) else {
        return err("invalid req_json: null or non-utf8 pointer");
    };
    into_cstr(enroll_impl(&raw))
}

#[cfg(feature = "enroll")]
#[derive(serde::Deserialize)]
struct GatewayReqJson {
    #[serde(default)]
    ctrl: Option<String>,
    #[serde(default)]
    control_server: Option<String>,
    #[serde(default)]
    auth_token: Option<String>,
    device_id: String,
}

/// Core gateway-resolve logic, shared by the C ABI and the Android JNI shim.
#[cfg(feature = "enroll")]
fn gateway_impl(raw: &str) -> Value {
    let parsed: GatewayReqJson = match serde_json::from_str(raw) {
        Ok(p) => p,
        Err(e) => return err_val(format!("req_json parse error: {e}")),
    };
    let ctrl = parsed.ctrl.or(parsed.control_server).unwrap_or_default();
    if ctrl.is_empty() {
        return err_val("gateway requires \"ctrl\" (or \"control_server\")");
    }
    if parsed.device_id.is_empty() {
        return err_val("gateway requires \"device_id\"");
    }
    let Some(rt) = runtime() else {
        return err_val("engine unavailable: tokio runtime build failed");
    };
    let auth_token = parsed.auth_token.unwrap_or_default();
    let client = fluxpeer_sdk::Client::with_password(ctrl.trim_end_matches('/').to_string(), &auth_token);
    match rt.block_on(client.gateway(&parsed.device_id)) {
        Ok(v) => ok_val(v),
        Err(e) => err_val(format!("gateway failed: {e:#}")),
    }
}

/// Resolve the gateway connect params for an enrolled device.
///
/// `req_json` = `{"ctrl":"<control-server>","device_id":"<id>","auth_token":"<token>"}`
/// (`control_server` also accepted; empty/missing `auth_token` sends no bearer).
/// `result` = `{node_pubkey, node_addr, node_port,
/// transport_protocol, iface_ipv4?, mtu?, dns, allowed_routes, config_epoch}` —
/// the node_* fields `/enroll` cannot provide; the caller merges them into the
/// `ClientStartReq` for `fp_connect_handshake_only`.
///
/// # Safety
/// `req_json` must be a valid NUL-terminated UTF-8 C string (or null).
#[cfg(feature = "enroll")]
#[unsafe(no_mangle)]
pub extern "C" fn fp_gateway(req_json: *const c_char) -> *mut c_char {
    let Some(raw) = cstr_to_string(req_json) else {
        return err("invalid req_json: null or non-utf8 pointer");
    };
    into_cstr(gateway_impl(&raw))
}
