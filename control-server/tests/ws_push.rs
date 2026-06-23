//! Integration test: the /devices/:id/watch WebSocket pushes a fresh config
//! whenever the network's config epoch changes.

use std::sync::Arc;

use fluxpeer_control_server::{router, state::Store};
use futures_util::StreamExt;
use tokio_tungstenite::connect_async;

#[tokio::test]
async fn ws_pushes_config_on_epoch_change() {
    // Seed a network + invite + one device to watch.
    let store = Arc::new(Store::new());
    let net = store.create_network("home");
    let inv = store.create_invite(&net.id, None, None).expect("invite");
    let d1 = store.enroll(&inv.code, "d1", "k1", 1000).expect("enroll d1");

    // Serve on an ephemeral port; keep a clone of the store to drive changes.
    let app = router(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let url = format!("ws://{addr}/api/v1/devices/{}/watch", d1.id);
    let (mut ws, _resp) = connect_async(&url).await.expect("ws connect");

    // 1) initial snapshot: device d1 has no peers yet.
    let first = ws.next().await.expect("msg").expect("ok").into_text().expect("text");
    let cfg: serde_json::Value = serde_json::from_str(&first).expect("json");
    assert_eq!(cfg["peers"].as_array().expect("peers").len(), 0);

    // 2) enroll a second device → epoch bump → push.
    store.enroll(&inv.code, "d2", "k2", 1000).expect("enroll d2");

    let second = ws.next().await.expect("msg2").expect("ok2").into_text().expect("text2");
    let cfg2: serde_json::Value = serde_json::from_str(&second).expect("json2");
    let peers = cfg2["peers"].as_array().expect("peers2");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["wg_public_key"], "k2");
}
