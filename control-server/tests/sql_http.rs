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

// A device pulling its own config presents its enroll-issued auth token (NOT the
// admin password) — the open `/devices/:id/*` routes are now per-device gated.
fn get_dev(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
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

/// Deterministic wg keypair (hex public key) for a test seed.
fn keypair(seed: u8) -> (fp_crypto::x25519::StaticSecret, String) {
    use fp_crypto::x25519::{PublicKey, StaticSecret};
    let sk = StaticSecret::from([seed; 32]);
    (sk.clone(), hex::encode(PublicKey::from(&sk).to_bytes()))
}

/// Run enroll round-1 (challenge) and return the proof-of-possession fields the
/// client sends in round-2: `(challenge_id, proof)`.
async fn pop_fields(app: &axum::Router, sk: &fp_crypto::x25519::StaticSecret, pub_hex: &str) -> (String, String) {
    use fp_crypto::x25519::PublicKey;
    let resp = app
        .clone()
        .oneshot(post("/api/v1/enroll/challenge", json!({ "wg_public_key": pub_hex })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "challenge should succeed for a valid key");
    let chal = body_json(resp).await;
    let cid = chal["challenge_id"].as_str().unwrap().to_string();
    let server_pub: [u8; 32] = hex::decode(chal["server_pub"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let proof = hex::encode(sk.diffie_hellman(&PublicKey::from(server_pub)).to_bytes());
    (cid, proof)
}

/// Full two-round enroll with proof-of-possession; returns the HTTP response.
async fn enroll_pop(app: &axum::Router, code: &str, name: &str, seed: u8) -> axum::response::Response {
    let (sk, pub_hex) = keypair(seed);
    let (cid, proof) = pop_fields(app, &sk, &pub_hex).await;
    app.clone()
        .oneshot(post(
            "/api/v1/enroll",
            json!({"invite_code": code, "name": name, "wg_public_key": pub_hex, "challenge_id": cid, "proof": proof}),
        ))
        .await
        .unwrap()
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

    // enroll without proof-of-possession is rejected (audit #11)
    let resp = app
        .clone()
        .oneshot(post(
            "/api/v1/enroll",
            json!({"invite_code": code, "name": "a", "wg_public_key": keypair(1).1}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "enroll without PoP must be 401");

    // a forged proof (right key, wrong DH) is rejected
    let (sk1, pub1) = keypair(1);
    let (cid, _good) = pop_fields(&app, &sk1, &pub1).await;
    let resp = app
        .clone()
        .oneshot(post(
            "/api/v1/enroll",
            json!({"invite_code": code, "name": "a", "wg_public_key": pub1, "challenge_id": cid, "proof": "00".repeat(32)}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "enroll with a forged proof must be 401");

    // enroll two devices with valid proof-of-possession (persisted; IP from DB state)
    let resp = enroll_pop(&app, &code, "a", 1).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let d1 = body_json(resp).await;
    assert_eq!(d1["address_v4"], "100.72.16.100");

    let resp = enroll_pop(&app, &code, "b", 2).await;
    let d2 = body_json(resp).await;
    let d2_id = d2["id"].as_str().unwrap().to_string();

    // config of d1 sees d2 as a peer (read back from DB) — authed with d1's token
    let resp = app
        .clone()
        .oneshot(get_dev(
            &format!("/api/v1/devices/{}/config", d1["id"].as_str().unwrap()),
            d1["auth_token"].as_str().unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cfg = body_json(resp).await;
    assert_eq!(cfg["peers"].as_array().unwrap().len(), 1);

    // a caller with NEITHER the device's token NOR admin creds is rejected (IDOR fix)
    let resp = app
        .clone()
        .oneshot(get_dev(
            &format!("/api/v1/devices/{}/config", d1["id"].as_str().unwrap()),
            "not-the-right-token",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // an admin automation bearer (master key) MAY read any device's config — admins
    // already see everything; only the unauthenticated-IDOR caller is the threat.
    let resp = app
        .clone()
        .oneshot(get(&format!("/api/v1/devices/{}/config", d1["id"].as_str().unwrap())))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // revoke d2 → its config is cut off (404)
    let resp = app
        .clone()
        .oneshot(del(&format!("/api/v1/devices/{d2_id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app
        .clone()
        .oneshot(get_dev(
            &format!("/api/v1/devices/{d2_id}/config"),
            d2["auth_token"].as_str().unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // bad invite → 403 (PoP passes, but the invite is rejected)
    let (sk3, pub3) = keypair(3);
    let (cid3, proof3) = pop_fields(&app, &sk3, &pub3).await;
    let resp = app
        .oneshot(post(
            "/api/v1/enroll",
            json!({"invite_code": "nope", "name": "x", "wg_public_key": pub3, "challenge_id": cid3, "proof": proof3}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
