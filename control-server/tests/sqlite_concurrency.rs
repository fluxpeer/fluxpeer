// SPDX-License-Identifier: BSD-3-Clause
//! File-backed, multi-pool HTTP contention regression for M-B/S6.
use std::sync::Arc;
use axum::{body::Body, http::{Request, StatusCode}, Router};
use fluxpeer_control_server::{sql_router, sql_store::SqlStore};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn call(app: &Router, method: &str, path: &str, token: &str, body: Value, expected: StatusCode) -> Value {
    let response = app.clone().oneshot(Request::builder().method(method).uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json").body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(status, expected, "{method} {path}: {}", String::from_utf8_lossy(&bytes));
    if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_config_endpoints_routes_and_enroll_never_return_5xx() {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    use fp_crypto::x25519::{PublicKey, StaticSecret};
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}?mode=rwc", dir.path().join("control.db").display());
    let first = Arc::new(SqlStore::connect(&url).await.unwrap());
    let second = Arc::new(SqlStore::connect(&url).await.unwrap());
    let net = first.create_network("contention").await.unwrap();
    let invite = first.create_invite(&net.id, None, None).await.unwrap();
    let key = hex::encode(PublicKey::from(&StaticSecret::from([99;32])).to_bytes());
    let (device, token) = first.enroll(&invite.code, "exit", &key, 0).await.unwrap();
    let salt = SaltString::encode_b64(b"contention-test-salt").unwrap();
    let hash = Argon2::default().hash_password(b"fixture-password", &salt).unwrap().to_string();
    first.create_admin("fixture", &hash, 0).await.unwrap();
    let apps = [sql_router(first), sql_router(second)];
    let mut admins = Vec::new();
    for app in &apps {
        let login = call(app, "POST", "/api/v1/admin/login", "", json!({"username":"fixture","password":"fixture-password"}), StatusCode::OK).await;
        admins.push(login["token"].as_str().unwrap().to_owned());
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(12));
    let mut tasks = tokio::task::JoinSet::new();
    for worker in 0..12 {
        let app = apps[worker % 2].clone(); let admin = admins[worker % 2].clone();
        let barrier = barrier.clone(); let id = device.id.clone(); let token = token.clone(); let invite = invite.code.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            match worker {
                0..=3 => for _ in 0..80 {
                    call(&app, "GET", &format!("/api/v1/devices/{id}/config"), &token, Value::Null, StatusCode::OK).await;
                },
                4..=7 => for port in 10000..10080 {
                    call(&app, "POST", &format!("/api/v1/devices/{id}/endpoints"), &token,
                        json!({"endpoints":[format!("192.0.2.1:{port}")]}), StatusCode::NO_CONTENT).await;
                },
                8..=9 => for iteration in 0..30 {
                    let route = call(&app, "POST", &format!("/api/v1/devices/{id}/routes"), &admin,
                        json!({"prefix":if worker == 8 { "0.0.0.0/0".to_owned() } else { format!("10.{worker}.{iteration}.0/24") }}), StatusCode::CREATED).await;
                    let route = route["id"].as_str().unwrap();
                    call(&app, "POST", &format!("/api/v1/routes/{route}/approve"), &admin, json!({}), StatusCode::NO_CONTENT).await;
                    call(&app, "DELETE", &format!("/api/v1/routes/{route}"), &admin, Value::Null, StatusCode::NO_CONTENT).await;
                },
                _ => for iteration in 0..20u8 {
                    let seed = (worker as u8 - 10) * 20 + iteration + 1;
                    let secret = StaticSecret::from([seed;32]); let key = hex::encode(PublicKey::from(&secret).to_bytes());
                    let challenge = call(&app, "POST", "/api/v1/enroll/challenge", "", json!({"wg_public_key":key}), StatusCode::OK).await;
                    let public: [u8;32] = hex::decode(challenge["server_pub"].as_str().unwrap()).unwrap().try_into().unwrap();
                    let proof = hex::encode(secret.diffie_hellman(&PublicKey::from(public)).to_bytes());
                    call(&app, "POST", "/api/v1/enroll", "", json!({"invite_code":invite,"name":"concurrent",
                        "wg_public_key":key,"challenge_id":challenge["challenge_id"],"proof":proof}), StatusCode::CREATED).await;
                },
            }
        });
    }
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
    }).await.unwrap();
}
