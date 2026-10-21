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

    // Both old registrations and explicit transport identities survive HTTP/SQL.
    for node_id in [Value::Null, json!("edge-sql")] {
        let resp = app.clone().oneshot(post("/api/v1/relays", json!({
            "region": "eu", "url": "localhost:443", "anytls": true, "node_id": node_id
        }))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(body_json(resp).await["node_id"], node_id);
    }
    for invalid in ["".into(), " ".into(), " edge".into(), "edge ".into(), "edge name".into(), "edge\n".into(), "é".into(), "x".repeat(129)] {
        let resp = app.clone().oneshot(post("/api/v1/relays", json!({
            "region": "eu", "url": "localhost:443", "node_id": invalid
        }))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
    let relays = body_json(app.clone().oneshot(get("/api/v1/networks/any/relays")).await.unwrap()).await;
    assert_eq!(relays.as_array().unwrap().len(), 2);
    assert!(relays.as_array().unwrap().iter().any(|r| r["node_id"] == "edge-sql"));

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

    // revoke d2 invalidates its token as well as cutting off its config
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
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

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

/// Exit contract over HTTP (AD-1/AD-2): approving a `0.0.0.0/0` route flips
/// `self_exit` in the exit device's own config and `exit` in every peer's view;
/// deleting the route revokes both.
#[tokio::test]
async fn exit_flags_over_http_follow_default_route_approval() {
    unsafe { std::env::set_var("FLUXPEER_ADMIN_PASSWORD", "test") };
    let store = Arc::new(
        SqlStore::connect("sqlite:file:memhttp_exit?mode=memory&cache=shared")
            .await
            .unwrap(),
    );
    let app = sql_router(store);

    let resp = app
        .clone()
        .oneshot(post("/api/v1/networks", json!({"name": "exit-net"})))
        .await
        .unwrap();
    let net_id = body_json(resp).await["id"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/networks/{net_id}/invites"),
            json!({"max_uses": 3}),
        ))
        .await
        .unwrap();
    let code = body_json(resp).await["code"].as_str().unwrap().to_string();

    let resp = enroll_pop(&app, &code, "exit", 11).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let exit_dev = body_json(resp).await;
    let exit_id = exit_dev["id"].as_str().unwrap().to_string();
    let exit_token = exit_dev["auth_token"].as_str().unwrap().to_string();
    let resp = enroll_pop(&app, &code, "client", 12).await;
    let client_dev = body_json(resp).await;
    let client_id = client_dev["id"].as_str().unwrap().to_string();
    let client_token = client_dev["auth_token"].as_str().unwrap().to_string();

    async fn config(app: &axum::Router, id: &str, token: &str) -> Value {
        let resp = app
            .clone()
            .oneshot(get_dev(&format!("/api/v1/devices/{id}/config"), token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp).await
    }
    let peer_exit = |cfg: &Value| -> bool {
        cfg["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["wg_public_key"].as_str() == Some(keypair(11).1.as_str()))
            .map(|p| p["exit"].as_bool().unwrap_or(false))
            .unwrap_or(false)
    };

    // Baseline: no default route → no exit flags.
    let cfg = config(&app, &exit_id, &exit_token).await;
    assert_eq!(cfg["self_exit"], false);
    let cfg = config(&app, &client_id, &client_token).await;
    assert!(!peer_exit(&cfg));

    // Reject invalid CIDRs; canonicalize host bits and noncanonical defaults.
    for prefix in ["1.2.3.4/33", "::/129", "not-a-prefix", "192.0.2.1"] {
        let resp = app.clone().oneshot(post(&format!("/api/v1/devices/{exit_id}/routes"), json!({"prefix": prefix}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{prefix}");
    }
    for (prefix, expected) in [("10.2.3.4/8", "10.0.0.0/8"), ("2001:db8::7/32", "2001:db8::/32")] {
        let resp = app.clone().oneshot(post(&format!("/api/v1/devices/{exit_id}/routes"), json!({"prefix": prefix}))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let route = body_json(resp).await;
        assert_eq!(route["prefix"], expected);
        let id = route["id"].as_str().unwrap();
        assert_eq!(app.clone().oneshot(del(&format!("/api/v1/routes/{id}"))).await.unwrap().status(), StatusCode::NO_CONTENT);
    }
    let resp = app.clone().oneshot(post(
        &format!("/api/v1/devices/{exit_id}/routes"), json!({"prefix": "1.2.3.4/00"}),
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let route = body_json(resp).await;
    assert_eq!(route["prefix"], "0.0.0.0/0");
    let route_id = route["id"].as_str().unwrap().to_string();
    let resp = app
        .clone()
        .oneshot(post(&format!("/api/v1/routes/{route_id}/approve"), json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let cfg = config(&app, &exit_id, &exit_token).await;
    assert_eq!(cfg["self_exit"], true, "approved default route must set self_exit");
    let cfg = config(&app, &client_id, &client_token).await;
    assert!(peer_exit(&cfg), "peer view must mark the exit device");

    // Revoke (delete) → both flags off again.
    let resp = app
        .clone()
        .oneshot(del(&format!("/api/v1/routes/{route_id}")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let cfg = config(&app, &exit_id, &exit_token).await;
    assert_eq!(cfg["self_exit"], false);
    let cfg = config(&app, &client_id, &client_token).await;
    assert!(!peer_exit(&cfg));
}

#[tokio::test]
async fn canonical_enrollment_rotates_http_credential_and_rejects_old_token() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let store = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    let network = store.create_network("key-contract").await.unwrap();
    let invite = store.create_invite(&network.id, None, Some(1)).await.unwrap();
    let app = sql_router(store.clone());
    let (private, public) = keypair(73);
    let base64 = STANDARD.encode(hex::decode(&public).unwrap());
    let mut responses = Vec::new();
    for encoding in [base64, public.to_uppercase()] {
        // Challenge and enrollment may use different encodings of the same bytes.
        let challenge_key = if encoding.len() == 44 { &encoding } else { &public };
        let (cid, proof) = pop_fields(&app, &private, challenge_key).await;
        let response = app.clone().oneshot(post("/api/v1/enroll", json!({
            "invite_code": invite.code, "name": "same-key", "wg_public_key": encoding,
            "challenge_id": cid, "proof": proof,
        }))).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        responses.push(body_json(response).await);
    }
    assert_eq!(responses[0]["id"], responses[1]["id"]);
    assert_eq!(responses[0]["address_v4"], responses[1]["address_v4"]);
    assert_eq!(responses[1]["wg_public_key"], public);
    let path = format!("/api/v1/devices/{}/config", responses[1]["id"].as_str().unwrap());
    let old_token = responses[0]["auth_token"].as_str().unwrap();
    let new_token = responses[1]["auth_token"].as_str().unwrap();
    assert_ne!(old_token, new_token);
    assert_eq!(app.clone().oneshot(get_dev(&path, old_token)).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(app.clone().oneshot(get_dev(&path, new_token)).await.unwrap().status(), StatusCode::OK);
    assert_eq!(store.list_devices(&network.id).await.unwrap().len(), 1);
    assert_eq!(store.list_invites(&network.id).await.unwrap()[0].uses, 1);
    for invalid in ["bad".to_owned(), "ff".repeat(31)] {
        let response = app.clone().oneshot(post("/api/v1/enroll/challenge", json!({"wg_public_key": invalid}))).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn revoked_key_rejoins_with_new_invite_and_possession_proof() {
    let store = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    let network = store.create_network("rejoin-http").await.unwrap();
    let invite = store.create_invite(&network.id, None, Some(1)).await.unwrap();
    let app = sql_router(store.clone());
    let first = enroll_pop(&app, &invite.code, "old", 92).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let old = body_json(first).await;
    let old_id = old["id"].as_str().unwrap();
    store.revoke_device(old_id).await.unwrap();
    let invite = store.create_invite(&network.id, None, Some(1)).await.unwrap();
    // A valid invitation never replaces proof of possession.
    let (_, public) = keypair(92);
    let no_proof = app.clone().oneshot(post("/api/v1/enroll", json!({
        "invite_code": invite.code, "name": "new", "wg_public_key": public
    }))).await.unwrap();
    assert_eq!(no_proof.status(), StatusCode::UNAUTHORIZED);
    let response = enroll_pop(&app, &invite.code, "new", 92).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let new = body_json(response).await;
    let new_id = new["id"].as_str().unwrap();
    assert_ne!(new_id, old_id);
    assert_ne!(new["auth_token"], old["auth_token"]);
    for path in [format!("/api/v1/devices/{old_id}/config"), format!("/api/v1/devices/{new_id}/config")] {
        assert_eq!(app.clone().oneshot(get_dev(&path, old["auth_token"].as_str().unwrap())).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(app.clone().oneshot(get_dev(&format!("/api/v1/devices/{new_id}/config"), new["auth_token"].as_str().unwrap())).await.unwrap().status(), StatusCode::OK);
    assert_eq!(store.list_devices(&network.id).await.unwrap().len(), 2);
    assert_eq!(store.list_invites(&network.id).await.unwrap().iter().find(|i| i.code == invite.code).unwrap().uses, 1);
    let invalid = app.oneshot(post("/api/v1/enroll", json!({"invite_code": invite.code,"name":"bad","wg_public_key":"bad"}))).await.unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
}
