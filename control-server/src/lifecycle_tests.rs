// SPDX-License-Identifier: BSD-3-Clause
//! Lifecycle contracts exercise the production SQL router, not the memory router.
use super::*;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use futures_util::{SinkExt, StreamExt};

async fn call(app: &Router, method: &str, path: &str, token: &str, body: Value, expected: StatusCode) -> Value {
    let req = Request::builder().method(method).uri(format!("/api/v1{path}"))
        .header("authorization", format!("Bearer {token}")).header("content-type", "application/json")
        .body(Body::from(body.to_string())).unwrap();
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), expected, "{method} {path}");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() }
}
async fn login(app: &Router, user: &str, password: &str) -> String {
    call(app, "POST", "/admin/login", "", json!({"username":user,"password":password}), StatusCode::OK).await["token"].as_str().unwrap().into()
}
async fn fixture() -> (Arc<SqlStore>, Router, String) {
    let store = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    let hash = Argon2::default().hash_password(b"password", &SaltString::encode_b64(b"lifecycle-salt").unwrap()).unwrap().to_string();
    for user in ["first", "second"] { store.create_admin(user, &hash, 0).await.unwrap(); }
    let app = sql_router(store.clone());
    let session = login(&app, "first", "password").await;
    (store, app, session)
}
async fn member(store: &SqlStore, network: &str, name: &str, key: u8) -> (domain::Device, String) {
    let invite = store.create_invite(network, None, None).await.unwrap();
    store.enroll(&invite.code, name, &hex::encode([key;32]), 0).await.unwrap()
}

#[tokio::test]
async fn password_change_and_deletion_revoke_all_sessions_including_other_instances() {
    let (store, app, first) = fixture().await;
    let other_instance = sql_router(store.clone());
    let first2 = login(&app, "first", "password").await;
    let remote = login(&other_instance, "first", "password").await;
    let second = login(&app, "second", "password").await;
    call(&app, "POST", "/admin/password", &first, json!({"old_password":"password","new_password":"new-password"}), StatusCode::NO_CONTENT).await;
    for (router, token) in [(&app, &first), (&app, &first2), (&other_instance, &remote)] {
        call(router, "GET", "/admin/me", token, Value::Null, StatusCode::UNAUTHORIZED).await;
        call(router, "POST", "/admin/admins", token, json!({"username":"attacker","password":"test"}), StatusCode::UNAUTHORIZED).await;
    }
    let updated = login(&app, "first", "new-password").await;
    let remote = login(&other_instance, "first", "new-password").await;
    call(&app, "DELETE", "/admin/admins/first", &second, Value::Null, StatusCode::NO_CONTENT).await;
    for (router, token) in [(&app, &updated), (&other_instance, &remote)] {
        call(router, "GET", "/admin/me", token, Value::Null, StatusCode::UNAUTHORIZED).await;
    }
    call(&app, "POST", "/admin/admins", &second, json!({"username":"first","password":"new-password"}), StatusCode::CREATED).await;
    call(&other_instance, "GET", "/admin/me", &remote, Value::Null, StatusCode::UNAUTHORIZED).await;
    call(&app, "GET", "/admin/me", &second, Value::Null, StatusCode::OK).await;
}

#[tokio::test]
async fn device_revocation_closes_every_device_endpoint_and_resolve_is_same_network() {
    let (store, app, session) = fixture().await;
    let net = store.create_network("home").await.unwrap();
    let (device, token) = member(&store, &net.id, "laptop", 11).await;
    let other = store.create_network("other").await.unwrap();
    let (_, foreign) = member(&store, &other.id, "foreign", 12).await;
    let path = format!("/networks/{}/resolve/laptop", net.id);
    for credential in [&token, &session] {
        let result = call(&app, "GET", &path, credential, Value::Null, StatusCode::OK).await;
        assert_eq!(result["address"], device.address_v4.clone().unwrap());
        assert_eq!(result["address_v6"], device.address_v6.clone().unwrap());
    }
    call(&app, "GET", &path, &foreign, Value::Null, StatusCode::FORBIDDEN).await;
    call(&app, "GET", &path, "invalid", Value::Null, StatusCode::UNAUTHORIZED).await;
    call(&app, "DELETE", &format!("/devices/{}", device.id), &session, Value::Null, StatusCode::NO_CONTENT).await;
    assert!(store.device_token(&device.id).await.unwrap().is_none());
    for suffix in ["config", "gateway", "stats", "settings", "routes"] {
        call(&app, "GET", &format!("/devices/{}/{suffix}", device.id), &token, Value::Null, StatusCode::UNAUTHORIZED).await;
    }
    for (suffix, body) in [("endpoints", json!({"endpoints":["127.0.0.1:1234"]})), ("stats", json!({"rx_bytes":1,"tx_bytes":2}))] {
        call(&app, "POST", &format!("/devices/{}/{suffix}", device.id), &token, body, StatusCode::UNAUTHORIZED).await;
    }
    call(&app, "GET", &path, &token, Value::Null, StatusCode::UNAUTHORIZED).await;
    call(&app, "GET", &path, &session, Value::Null, StatusCode::NOT_FOUND).await;
    assert!(store.set_endpoints(&device.id, &[]).await.is_err());
    assert!(store.report_stats(&device.id, 1, 2, "[]", 0).await.is_err());
}

#[tokio::test]
async fn sdk_invite_and_network_deletion_cascade_and_preserve_unrelated_network() {
    let (store, app, session) = fixture().await;
    let net = store.create_network("delete").await.unwrap();
    let (device, token) = member(&store, &net.id, "laptop", 21).await;
    let other = store.create_network("keep").await.unwrap();
    let (untouched, other_token) = member(&store, &other.id, "other", 22).await;
    let invite = store.create_invite(&net.id, None, None).await.unwrap();
    let route = store.advertise_route(&device.id, "10.0.0.0/24").await.unwrap();
    store.approve_route(&route.id).await.unwrap();
    store.report_stats(&device.id, 10, 20, "[]", 1).await.unwrap();
    let mut epoch = store.subscribe(&net.id);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    let admin = fluxpeer_sdk::Client::with_password(format!("http://{address}"), &session);
    let member_client = fluxpeer_sdk::Client::with_password(format!("http://{address}"), &token);
    assert_eq!(member_client.resolve(&net.id, "laptop").await.unwrap()["address"], device.address_v4.unwrap());
    assert!(member_client.revoke_invite(&net.id, &invite.code).await.is_err());
    assert!(admin.revoke_invite(&other.id, &invite.code).await.is_err());
    admin.revoke_invite(&net.id, &invite.code).await.unwrap();
    assert!(store.enroll(&invite.code, "denied", &hex::encode([23;32]), 0).await.is_err());
    assert!(admin.delete_network(&net.id, "wrong-id").await.is_err());
    assert!(store.device_config(&device.id).await.is_ok());
    assert!(member_client.delete_network(&net.id, &net.id).await.is_err());
    admin.delete_network(&net.id, &net.id).await.unwrap();
    epoch.changed().await.unwrap();
    assert!(*epoch.borrow() > 0);
    assert!(store.device_token(&device.id).await.unwrap().is_none());
    assert!(store.device_config(&device.id).await.is_err());
    assert!(store.list_invites(&net.id).await.unwrap().is_empty());
    assert!(store.list_device_routes(&device.id).await.unwrap().is_empty());
    assert!(store.device_stats(&device.id).await.unwrap().is_none());
    assert!(member_client.device_config(&device.id).await.is_err());
    assert!(store.create_invite(&net.id, None, None).await.is_err());
    assert!(store.advertise_route(&device.id, "10.1.0.0/24").await.is_err());
    assert_eq!(store.device_token(&untouched.id).await.unwrap(), Some(other_token));
    assert!(store.device_config(&untouched.id).await.is_ok());
    server.abort();
}

async fn watch(address: std::net::SocketAddr, id: &str, token: &str) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Box<tokio_tungstenite::tungstenite::Error>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut req = format!("ws://{address}/api/v1/devices/{id}/watch").into_client_request().unwrap();
    req.headers_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
    tokio_tungstenite::connect_async(req).await.map(|(socket, _)| socket).map_err(Box::new)
}
async fn wait_released(store: &SqlStore, network: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while store.watcher_count(network) != 0 { tokio::time::sleep(std::time::Duration::from_millis(10)).await; }
    }).await.unwrap();
}
#[tokio::test]
async fn watch_disconnect_releases_subscription_and_revocation_rejects_reconnect() {
    let (store, app, _) = fixture().await;
    let net = store.create_network("watch").await.unwrap();
    let (device, token) = member(&store, &net.id, "watcher", 31).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    for graceful in [true, false] {
        let mut socket = watch(address, &device.id, &token).await.unwrap();
        assert!(socket.next().await.unwrap().unwrap().is_text());
        assert_eq!(store.watcher_count(&net.id), 1);
        if graceful { socket.close(None).await.unwrap(); }
        drop(socket);
        wait_released(&store, &net.id).await;
    }
    let mut socket = watch(address, &device.id, &token).await.unwrap();
    socket.next().await.unwrap().unwrap();
    socket.send(tokio_tungstenite::tungstenite::Message::Ping(vec![1,2,3])).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop { if socket.next().await.unwrap().unwrap().is_pong() { break; } }
    }).await.unwrap();
    store.revoke_device(&device.id).await.unwrap();
    wait_released(&store, &net.id).await;
    let error = watch(address, &device.id, &token).await.unwrap_err();
    assert!(matches!(*error, tokio_tungstenite::tungstenite::Error::Http(response) if response.status() == StatusCode::UNAUTHORIZED));
    server.abort();
}

#[tokio::test]
async fn silent_watch_times_out_and_drops_its_subscription() {
    let (store, _, _) = fixture().await;
    let net = store.create_network("idle").await.unwrap();
    let (device, token) = member(&store, &net.id, "silent", 32).await;
    let state = store.clone();
    let id = device.id.clone();
    let network = net.id.clone();
    let app = Router::new().route("/idle", get(move |ws: WebSocketUpgrade| async move {
        let rx = state.subscribe(&network);
        ws.on_upgrade(move |socket| sql_watch_loop_with_idle(socket, state, id,
            WatchCredential { bearer: token, master: false }, rx, std::time::Duration::from_millis(120)))
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/idle")).await.unwrap();
    assert!(socket.next().await.unwrap().unwrap().is_text());
    // Keep the transport open but do not read/respond to the server's ping.
    wait_released(&store, &net.id).await;
    drop(socket); server.abort();
}
