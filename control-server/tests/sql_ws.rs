//! Integration test: persistent WS push (SqlStore-backed) pushes config on
//! epoch change, verified end-to-end on in-memory SQLite.

use std::sync::Arc;

use fluxpeer_control_server::{sql_router, sql_store::SqlStore};
use futures_util::StreamExt;
use tokio_tungstenite::connect_async;

#[tokio::test]
async fn persistent_ws_pushes_on_enroll() {
    let store = Arc::new(
        SqlStore::connect("sqlite:file:memsqlws?mode=memory&cache=shared")
            .await
            .unwrap(),
    );
    let net = store.create_network("home").await.unwrap();
    let inv = store.create_invite(&net.id, None, None).await.unwrap();
    let d1 = store.enroll(&inv.code, "d1", "k1", 1000).await.unwrap();

    let app = sql_router(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let url = format!("ws://{addr}/api/v1/devices/{}/watch", d1.id);
    let (mut ws, _) = connect_async(&url).await.unwrap();

    // initial snapshot: no peers
    let first = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(cfg["peers"].as_array().unwrap().len(), 0);

    // enroll a 2nd device → DB epoch bump → push
    store.enroll(&inv.code, "d2", "k2", 1000).await.unwrap();

    let second = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let cfg2: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_eq!(cfg2["peers"].as_array().unwrap().len(), 1);
    assert_eq!(cfg2["peers"][0]["wg_public_key"], "k2");
}
