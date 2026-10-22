// SPDX-License-Identifier: BSD-3-Clause
//! M-B workload with real watch sockets and bounded HTTP operations.
use super::*;
use axum::{body::Body, http::Request};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tower::ServiceExt;

async fn request(app: &Router, method: &str, path: &str, token: &str, body: Value, status: StatusCode) -> Value {
    let request = Request::builder().method(method).uri(path).header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json").body(Body::from(body.to_string())).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), app.clone().oneshot(request)).await
        .unwrap_or_else(|_| panic!("HTTP await stalled: {method} {path}")).unwrap();
    let actual = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(actual, status, "{method} {path}: {}", String::from_utf8_lossy(&bytes));
    if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() }
}

// Same authentication and watch loop, with a shorter heartbeat for the default
// workspace run. Long mode uses the unmodified production watch endpoint.
async fn fast_watch(State(store): State<Arc<SqlStore>>, Path(id): Path<String>, headers: axum::http::HeaderMap, ws: WebSocketUpgrade) -> Result<Response, StatusCode> {
    require_device(&store, &headers, &id).await?;
    let network = store.network_of(&id).await.map_err(sql_status)?.ok_or(StatusCode::NOT_FOUND)?;
    let credential = WatchCredential { bearer: bearer_token(&headers).unwrap().into(), master: false };
    let updates = store.subscribe(&network);
    Ok(ws.on_upgrade(move |socket| sql_watch_loop_with_idle(socket, store, id, credential, updates, Duration::from_millis(600))))
}

async fn workload(duration: Duration, long: bool) {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use fp_crypto::x25519::{PublicKey, StaticSecret};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message as WsMessage};
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}?mode=rwc", dir.path().join("control.db").display());
    let store = Arc::new(SqlStore::connect(&url).await.unwrap());
    let net = store.create_network("mb-hang").await.unwrap();
    let invite = store.create_invite(&net.id, None, None).await.unwrap();
    let mut devices = Vec::new();
    for seed in [99, 100] {
        let key = hex::encode(PublicKey::from(&StaticSecret::from([seed;32])).to_bytes());
        devices.push(store.enroll(&invite.code, "node", &key, 0).await.unwrap());
    }
    let hash = Argon2::default().hash_password(b"fixture-password", &SaltString::encode_b64(b"mb-hang-test-salt").unwrap()).unwrap().to_string();
    store.create_admin("fixture", &hash, 0).await.unwrap();
    let app = sql_router(store.clone()).merge(Router::new().route("/fast-watch/:id", get(fast_watch)).with_state(store.clone()));
    let login = request(&app, "POST", "/api/v1/admin/login", "", json!({"username":"fixture","password":"fixture-password"}), StatusCode::OK).await;
    let admin = login["token"].as_str().unwrap().to_owned();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap(); let served = app.clone();
    let server = tokio::spawn(async move { axum::serve(listener, served).await.unwrap(); });
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let counts: Arc<[AtomicU64; 6]> = Arc::new(std::array::from_fn(|_| AtomicU64::new(0)));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..8 {
        let (device, token) = &devices[index % 2];
        let path = if long { format!("/api/v1/devices/{}/watch", device.id) } else { format!("/fast-watch/{}", device.id) };
        let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
        req.headers_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
        let (mut socket, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        let mut stop = stopping.clone(); let counts = counts.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.changed() => { let _ = socket.close(None).await; break; },
                    incoming = socket.next() => match incoming.unwrap().unwrap() {
                        WsMessage::Text(_) => { counts[4].fetch_add(1, Ordering::Relaxed); },
                        WsMessage::Ping(data) => { counts[5].fetch_add(1, Ordering::Relaxed); socket.send(WsMessage::Pong(data)).await.unwrap(); },
                        WsMessage::Pong(_) => {},
                        other => panic!("watch unexpectedly closed: {other:?}"),
                    },
                }
            }
        });
    }
    let until = tokio::time::Instant::now() + duration;
    for index in 0..6 {
        let (device, token) = devices[index % 2].clone(); let app = app.clone(); let counts = counts.clone();
        tasks.spawn(async move {
            while tokio::time::Instant::now() < until {
                let path = format!("/api/v1/devices/{}", device.id);
                match index / 2 {
                    0 => { request(&app, "GET", &format!("{path}/config"), &token, Value::Null, StatusCode::OK).await; },
                    1 => { request(&app, "POST", &format!("{path}/stats"), &token, json!({"rx_bytes":1,"tx_bytes":2,"peers":[]}), StatusCode::NO_CONTENT).await; },
                    _ => { request(&app, "POST", &format!("{path}/endpoints"), &token, json!({"endpoints":["192.0.2.1:1234"]}), StatusCode::NO_CONTENT).await; },
                }
                counts[index / 2].fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }
    let route_app = app.clone(); let route_admin = admin.clone(); let id = devices[0].0.id.clone(); let route_counts = counts.clone();
    tasks.spawn(async move {
        while tokio::time::Instant::now() < until {
            let route = request(&route_app, "POST", &format!("/api/v1/devices/{id}/routes"), &route_admin, json!({"prefix":"0.0.0.0/0"}), StatusCode::CREATED).await;
            let id = route["id"].as_str().unwrap();
            request(&route_app, "POST", &format!("/api/v1/routes/{id}/approve"), &route_admin, json!({}), StatusCode::NO_CONTENT).await;
            request(&route_app, "DELETE", &format!("/api/v1/routes/{id}"), &route_admin, Value::Null, StatusCode::NO_CONTENT).await;
            route_counts[3].fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    tasks.spawn(async move {
        let secret = StaticSecret::from([7;32]); let key = hex::encode(PublicKey::from(&secret).to_bytes());
        while tokio::time::Instant::now() < until {
            let challenge = request(&app, "POST", "/api/v1/enroll/challenge", "", json!({"wg_public_key":key}), StatusCode::OK).await;
            let public: [u8;32] = hex::decode(challenge["server_pub"].as_str().unwrap()).unwrap().try_into().unwrap();
            let proof = hex::encode(secret.diffie_hellman(&PublicKey::from(public)).to_bytes());
            let device = request(&app, "POST", "/api/v1/enroll", "", json!({"invite_code":invite.code,"name":"restarting",
                "wg_public_key":key,"challenge_id":challenge["challenge_id"],"proof":proof}), StatusCode::CREATED).await;
            let id = device["id"].as_str().unwrap();
            request(&app, "DELETE", &format!("/api/v1/devices/{id}"), &admin, Value::Null, StatusCode::NO_CONTENT).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    tokio::time::sleep_until(until).await;
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
    }).await.expect("workload shutdown stalled");
    let measured: Vec<_> = counts.iter().map(|value| value.load(Ordering::Relaxed)).collect();
    eprintln!("M-B workload counters [config, stats, endpoints, route cycles, WS config, WS heartbeat]: {measured:?}");
    assert!(measured.iter().all(|count| *count > 0));
    server.abort(); let _ = server.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while store.watcher_count(&net.id) != 0 { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.unwrap();
}

#[test]
fn sqlite_mb_http_watch_workload_has_bounded_completion() {
    let seconds = std::env::var("FLUXPEER_CONTROL_STRESS_SECONDS").ok().map(|s| s.parse::<u64>().unwrap()).unwrap_or(3);
    let long = seconds >= 32;
    let (done, result) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        runtime.block_on(workload(Duration::from_secs(seconds), long));
        runtime.shutdown_timeout(Duration::from_secs(1));
        done.send(()).unwrap();
    });
    // Independent watchdog also detects a synchronous runtime deadlock where
    // Tokio timers cannot be polled. No remote process or real node is started.
    result.recv_timeout(Duration::from_secs(seconds + 25)).expect("control runtime watchdog expired");
    worker.join().unwrap();
}
