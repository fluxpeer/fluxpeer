//! Integration test: the persistent (SqlStore-backed) HTTP API end-to-end on an
//! in-memory SQLite DB. Proves HTTP → SqlStore → SQL wiring; production points
//! the same code at PostgreSQL.

use std::sync::Arc;

use fluxpeer_control_server::{sql_router, sql_store::SqlStore};
use http_body_util::BodyExt;
use tower::ServiceExt;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

// The management routes are bearer-gated (require_admin); the master password is
// FLUXPEER_ADMIN_PASSWORD (set to "test" by the test). Open routes ignore the header.
fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", "Bearer test")
        .body(Body::empty())
        .unwrap()
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", "Bearer test")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn del(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("authorization", "Bearer test")
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn persistent_http_enroll_loop_on_sqlite() {
    // Management routes are admin-gated; set the master bearer the helpers send.
    unsafe { std::env::set_var("FLUXPEER_ADMIN_PASSWORD", "test") };
    let store = Arc::new(
        SqlStore::connect("sqlite:file:memhttp?mode=memory&cache=shared")
            .await
            .unwrap(),
    );
    let app = sql_router(store);

    // create network
    let resp = app
        .clone()
        .oneshot(post("/api/v1/networks", json!({"name": "home"})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let net_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    // list networks
    let resp = app.clone().oneshot(get("/api/v1/networks")).await.unwrap();
    assert_eq!(body_json(resp).await.as_array().unwrap().len(), 1);

    // invite
    let resp = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/networks/{net_id}/invites"),
            json!({"max_uses": 5}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let code = body_json(resp).await["code"].as_str().unwrap().to_string();

    // enroll two devices (persisted; IP allocated from DB state)
    let resp = app
        .clone()
        .oneshot(post(
            "/api/v1/enroll",
            json!({"invite_code": code, "name": "a", "wg_public_key": "k1"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let d1 = body_json(resp).await;
    assert_eq!(d1["address_v4"], "100.72.16.100");

    let resp = app
        .clone()
        .oneshot(post(
            "/api/v1/enroll",
            json!({"invite_code": code, "name": "b", "wg_public_key": "k2"}),
        ))
        .await
        .unwrap();
    let d2_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    // config of d1 sees d2 as a peer (read back from DB)
    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/devices/{}/config", d1["id"].as_str().unwrap())))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cfg = body_json(resp).await;
    assert_eq!(cfg["peers"].as_array().unwrap().len(), 1);

    // revoke d2 → its config is cut off (404)
    let resp = app
        .clone()
        .oneshot(del(&format!("/api/v1/devices/{d2_id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/devices/{d2_id}/config")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // bad invite → 403
    let resp = app
        .oneshot(post(
            "/api/v1/enroll",
            json!({"invite_code": "nope", "name": "x", "wg_public_key": "k"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
