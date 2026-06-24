use std::ffi::{CStr, CString};
use std::sync::Arc;

use fluxpeer_control_server::{sql_router, sql_store::SqlStore};
use fp_crypto::x25519::StaticSecret;
use serde_json::{Value, json};

fn private_key_hex(seed: u8) -> String {
    hex::encode(StaticSecret::from([seed; 32]).to_bytes())
}

fn ffi_gateway_blocking(req: Value) -> Value {
    let raw = CString::new(req.to_string()).expect("gateway request json has no nul");
    let ptr = fp_node_client_sys::ffi::fp_gateway(raw.as_ptr());
    assert!(!ptr.is_null(), "fp_gateway returned null");
    let out = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("fp_gateway returned utf8")
        .to_string();
    unsafe { fp_node_client_sys::ffi::fp_free_string(ptr) };
    serde_json::from_str(&out).expect("fp_gateway returned json")
}

async fn ffi_gateway(req: Value) -> Value {
    tokio::task::spawn_blocking(move || ffi_gateway_blocking(req))
        .await
        .expect("ffi gateway blocking task")
}

async fn spawn_sql_control() -> String {
    let db = format!(
        "sqlite:file:ffi_gateway_auth_{}?mode=memory&cache=shared",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let store = Arc::new(SqlStore::connect(&db).await.expect("connect sqlite store"));
    let app = sql_router(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test control server");
    let addr = listener.local_addr().expect("test control server addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test control server");
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn ffi_gateway_requires_and_accepts_device_auth_token() {
    unsafe { std::env::set_var("FLUXPEER_ADMIN_PASSWORD", "test") };
    let base = spawn_sql_control().await;

    let admin = fluxpeer_sdk::Client::with_password(&base, "test");
    let net = admin.create_network("home").await.expect("create network");
    let net_id = net["id"].as_str().expect("network id");
    let invite = admin
        .create_invite(net_id, Some(4), None)
        .await
        .expect("create invite");
    let code = invite["code"].as_str().expect("invite code");

    let gateway = fluxpeer_sdk::Client::new(&base)
        .enroll(code, "gateway", &private_key_hex(7))
        .await
        .expect("enroll gateway");
    let gateway_id = gateway["id"].as_str().expect("gateway id");
    let gateway_token = gateway["auth_token"].as_str().expect("gateway token");
    let gateway_pub = gateway["wg_public_key"].as_str().expect("gateway pubkey");

    fluxpeer_sdk::Client::with_password(&base, gateway_token)
        .set_endpoints(gateway_id, &["203.0.113.7:41820".to_string()])
        .await
        .expect("gateway reports endpoint");

    let mobile = fluxpeer_sdk::Client::new(&base)
        .enroll(code, "mobile", &private_key_hex(9))
        .await
        .expect("enroll mobile");
    let mobile_id = mobile["id"].as_str().expect("mobile id");
    let mobile_token = mobile["auth_token"].as_str().expect("mobile token");

    let no_token = ffi_gateway(json!({
        "ctrl": base.clone(),
        "device_id": mobile_id,
    }))
    .await;
    assert_eq!(no_token["code"], 201);
    let message = no_token["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("401") || message.contains("Unauthorized"),
        "expected no-token gateway call to expose 401, got: {message}"
    );

    let authed = ffi_gateway(json!({
        "ctrl": base.clone(),
        "device_id": mobile_id,
        "auth_token": mobile_token,
    }))
    .await;
    assert_eq!(authed["code"], 200, "authed gateway call failed: {authed}");
    assert_eq!(authed["result"]["node_pubkey"], gateway_pub);
    assert_eq!(authed["result"]["node_addr"], "203.0.113.7");
    assert_eq!(authed["result"]["node_port"], 41820);
}
