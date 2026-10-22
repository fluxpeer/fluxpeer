// SPDX-License-Identifier: BSD-3-Clause
#![cfg(test)]
//! Exercise the production SQL router with a real login session and device tokens.

use std::sync::Arc;
use axum::{body::Body, http::{Request, StatusCode}};
use fluxpeer_control_server::{sql_router, sql_store::SqlStore};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn request(method: &str, path: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut req = Request::builder().method(method).uri(format!("/api/v1{path}"));
    if let Some(token) = token { req = req.header("authorization", format!("Bearer {token}")); }
    req.header("content-type", "application/json").body(Body::from(body.to_string())).unwrap()
}

async fn json_response(app: &axum::Router, method: &str, path: &str, token: Option<&str>, body: Value, expected: StatusCode) -> Value {
    let response = app.clone().oneshot(request(method, path, token, body)).await.unwrap();
    assert_eq!(response.status(), expected, "{method} {path}");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() }
}

#[test]
fn admin_login_reads_drawer_and_device_tokens_stay_confined() {
    // Set the master only in an isolated child before any runtime threads exist.
    const CHILD: &str = "FLUXPEER_TEST_ADMIN_CONFIG_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "admin_login_reads_drawer_and_device_tokens_stay_confined", "--nocapture"])
            .env(CHILD, "1").env("FLUXPEER_ADMIN_PASSWORD", "test-admin-config")
            .output().unwrap();
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return;
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let store = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
        use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
        let salt = SaltString::encode_b64(b"t0035-test-salt").unwrap();
        let hash = Argon2::default().hash_password(b"test-admin-config", &salt).unwrap().to_string();
        store.create_admin("admin", &hash, 0).await.unwrap();
        let network = store.create_network("drawer").await.unwrap();
        let invite = store.create_invite(&network.id, None, None).await.unwrap();
        let (device, own_token) = store.enroll(&invite.code, "drawer-device", &"11".repeat(32), 0).await.unwrap();
        let (_, other_token) = store.enroll(&invite.code, "other-device", &"22".repeat(32), 0).await.unwrap();
        let other_network = store.create_network("unrelated").await.unwrap();
        let other_invite = store.create_invite(&other_network.id, None, None).await.unwrap();
        let (_, unrelated_token) = store.enroll(&other_invite.code, "unrelated-device", &"33".repeat(32), 0).await.unwrap();
        let app = sql_router(store);
        let login = json_response(&app, "POST", "/admin/login", None,
            json!({"username":"admin", "password":"test-admin-config"}), StatusCode::OK).await;
        let session = login["token"].as_str().unwrap();
        assert_ne!(session, "test-admin-config");
        assert_eq!(json_response(&app, "GET", "/admin/me", Some(session), Value::Null, StatusCode::OK).await["username"], "admin");

        // This is the drawer's exact read set, including its Traffic tab.
        for suffix in ["config", "routes", "settings", "stats"] {
            let path = format!("/devices/{}/{suffix}", device.id);
            for token in [session, "test-admin-config", own_token.as_str()] {
                let value = json_response(&app, "GET", &path, Some(token), Value::Null, StatusCode::OK).await;
                if suffix == "config" { assert_eq!(value["address_v4"].as_str(), device.address_v4.as_deref()); }
            }
            for token in [&other_token, &unrelated_token] {
                json_response(&app, "GET", &path, Some(token), Value::Null, StatusCode::FORBIDDEN).await;
            }
            for token in [None, Some("invalid-or-expired-session"), Some("")] {
                json_response(&app, "GET", &path, token, Value::Null, StatusCode::UNAUTHORIZED).await;
            }
        }

        // Route approval in the UI immediately refetches routes and config.
        let routes = format!("/devices/{}/routes", device.id);
        let route = json_response(&app, "POST", &routes, Some(session), json!({"prefix":"10.35.0.0/24"}), StatusCode::CREATED).await;
        json_response(&app, "POST", &format!("/routes/{}/approve", route["id"].as_str().unwrap()), Some(session), Value::Null, StatusCode::NO_CONTENT).await;
        let refreshed = json_response(&app, "GET", &routes, Some(session), Value::Null, StatusCode::OK).await;
        assert!(refreshed.as_array().unwrap().iter().any(|r| r["id"] == route["id"] && r["approved"] == true));
        json_response(&app, "GET", &format!("/devices/{}/config", device.id), Some(session), Value::Null, StatusCode::OK).await;

        // Adding admin read authority must not grant node writes to a session,
        // or grant administrative writes to a device token.
        for (suffix, body) in [("endpoints", json!({"endpoints":[]})), ("stats", json!({"rx_bytes":1,"tx_bytes":2}))] {
            json_response(&app, "POST", &format!("/devices/{}/{suffix}", device.id), Some(session), body, StatusCode::UNAUTHORIZED).await;
        }
        for (method, suffix, body) in [("PUT", "settings", json!({"mtu":1280})), ("POST", "routes", json!({"prefix":"10.36.0.0/24"}))] {
            json_response(&app, method, &format!("/devices/{}/{suffix}", device.id), Some(&own_token), body, StatusCode::UNAUTHORIZED).await;
        }
        json_response(&app, "PUT", &format!("/devices/{}/settings", device.id), Some(session), json!({"mtu":1280}), StatusCode::NO_CONTENT).await;
        assert_eq!(json_response(&app, "GET", &format!("/devices/{}/settings", device.id), Some(session), Value::Null, StatusCode::OK).await["mtu"], 1280);
    });
}
