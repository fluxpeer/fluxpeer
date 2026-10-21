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
    let (d1, d1_token) = store.enroll(&inv.code, "d1", "6ab9f1eb8f7d3388f4f9d586f66e99fd54080df2c446f0e58668b09c08a16dd0", 1000).await.unwrap();

    let app = sql_router(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let url = format!("ws://{addr}/api/v1/devices/{}/watch", d1.id);
    // The watch endpoint is per-device gated; present d1's token on the handshake.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("authorization", format!("Bearer {d1_token}").parse().unwrap());
    let (mut ws, _) = connect_async(req).await.unwrap();

    // initial snapshot: no peers
    let first = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(cfg["peers"].as_array().unwrap().len(), 0);

    // enroll a 2nd device → DB epoch bump → push
    store.enroll(&inv.code, "d2", "015f7e6bc5aeaf483724089e9252cc13b50951a6b69412522765cff4d780306e", 1000).await.unwrap();

    let second = ws.next().await.unwrap().unwrap().into_text().unwrap();
    let cfg2: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_eq!(cfg2["peers"].as_array().unwrap().len(), 1);
    assert_eq!(cfg2["peers"][0]["wg_public_key"], "015f7e6bc5aeaf483724089e9252cc13b50951a6b69412522765cff4d780306e");
}

#[tokio::test]
async fn rotated_token_watch_cannot_receive_subsequent_config() {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
    let store = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    let net = store.create_network("rotation").await.unwrap();
    let invite = store.create_invite(&net.id, None, None).await.unwrap();
    let (device, old_token) = store.enroll(&invite.code, "device", &"11".repeat(32), 0).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/api/v1/devices/{}/watch", listener.local_addr().unwrap(), device.id);
    let app = sql_router(store.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    let request = |token: &str| {
        let mut req = url.clone().into_client_request().unwrap();
        req.headers_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    };
    let (mut old, _) = connect_async(request(&old_token)).await.unwrap();
    assert!(matches!(old.next().await, Some(Ok(Message::Text(_)))));
    let (_, token) = store.enroll(&invite.code, "repeat", &"11".repeat(32), 0).await.unwrap();
    store.enroll(&invite.code, "new peer", &"22".repeat(32), 0).await.unwrap();
    let next = tokio::time::timeout(std::time::Duration::from_secs(2), old.next()).await.unwrap();
    assert!(matches!(next, None | Some(Ok(Message::Close(_)))));
    assert!(connect_async(request(&old_token)).await.is_err());
    let (mut new, _) = connect_async(request(&token)).await.unwrap();
    assert!(matches!(new.next().await, Some(Ok(Message::Text(_)))));
    server.abort();
}
