// SPDX-License-Identifier: BSD-3-Clause
//! The master key is configured before the isolated child starts any threads.

#[test]
fn master_watch_survives_device_token_rotation() {
    const CHILD: &str = "FLUXPEER_TEST_MASTER_WATCH_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "master_watch_survives_device_token_rotation", "--nocapture"])
            .env(CHILD, "1")
            .env("FLUXPEER_ADMIN_PASSWORD", "test-master-watch")
            .output().unwrap();
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return;
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        use std::sync::Arc;
        use fluxpeer_control_server::{sql_router, sql_store::SqlStore};
        use futures_util::StreamExt;
        use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, Message}};
        let store = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
        let net = store.create_network("master-watch").await.unwrap();
        let invite = store.create_invite(&net.id, None, None).await.unwrap();
        let (device, token) = store.enroll(&invite.code, "device", &"11".repeat(32), 0).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/api/v1/devices/{}/watch", listener.local_addr().unwrap(), device.id);
        let app = sql_router(store.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let request = |bearer: &str| {
            let mut req = url.clone().into_client_request().unwrap();
            req.headers_mut().insert("authorization", format!("Bearer {bearer}").parse().unwrap());
            req
        };
        assert!(connect_async(request("wrong-master-key")).await.is_err());
        let (mut master, _) = connect_async(request("test-master-watch")).await.unwrap();
        let (mut old_device, _) = connect_async(request(&token)).await.unwrap();
        for socket in [&mut master, &mut old_device] {
            let first = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next()).await.unwrap();
            assert!(matches!(first, Some(Ok(Message::Text(_)))));
        }
        store.enroll(&invite.code, "rotate", &"11".repeat(32), 0).await.unwrap();
        store.enroll(&invite.code, "new peer", &"22".repeat(32), 0).await.unwrap();
        let pushed = tokio::time::timeout(std::time::Duration::from_secs(2), master.next()).await.unwrap().unwrap().unwrap();
        let cfg: serde_json::Value = serde_json::from_str(&pushed.into_text().unwrap()).unwrap();
        assert_eq!(cfg["peers"].as_array().unwrap().len(), 1);
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), old_device.next()).await.unwrap();
        assert!(matches!(closed, None | Some(Ok(Message::Close(_)))));
        server.abort();
    });
}
