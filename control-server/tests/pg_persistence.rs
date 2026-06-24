//! Real-PostgreSQL validation of the persistent (SqlStore-backed) path.
//!
//! The in-memory SQLite tests prove the SQL wiring and dialect portability, but
//! cannot prove **durability across a process restart** — the whole point of
//! persistence. This test does, on a real PostgreSQL server:
//! 1. run the full enroll/revoke coordination loop through `sql_router`,
//! 2. DROP the store (simulating a control-server restart),
//! 3. reconnect a fresh `SqlStore` to the SAME database, and
//! 4. assert every network/invite/device survived and the API still serves it.
//!
//! Gated on `DATABASE_URL` (e.g. `postgres://fluxpeer:fluxpeer@127.0.0.1/fluxpeer`).
//! When it is unset the test is a clearly-logged no-op so `cargo test` stays green
//! in environments without a database (CI sandbox), without faking a PG result.

use std::sync::Arc;

use fluxpeer_control_server::{persistence as db, sql_router, sql_store::SqlStore};
use http_body_util::BodyExt;
use tower::ServiceExt;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}
fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
fn del(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}
async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Full two-round enroll with proof-of-possession (audit #11); returns the response.
async fn enroll_pop(app: &axum::Router, code: &str, name: &str, seed: u8) -> axum::response::Response {
    use fp_crypto::x25519::{PublicKey, StaticSecret};
    let sk = StaticSecret::from([seed; 32]);
    let pub_hex = hex::encode(PublicKey::from(&sk).to_bytes());
    let resp = app
        .clone()
        .oneshot(post("/api/v1/enroll/challenge", json!({ "wg_public_key": pub_hex })))
        .await
        .unwrap();
    let chal = body_json(resp).await;
    let server_pub: [u8; 32] = hex::decode(chal["server_pub"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let proof = hex::encode(sk.diffie_hellman(&PublicKey::from(server_pub)).to_bytes());
    app.clone()
        .oneshot(post(
            "/api/v1/enroll",
            json!({
                "invite_code": code,
                "name": name,
                "wg_public_key": pub_hex,
                "challenge_id": chal["challenge_id"].as_str().unwrap(),
                "proof": proof,
            }),
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn persistence_survives_restart_on_postgres() {
    let Some(url) = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty()) else {
        eprintln!("SKIP persistence_survives_restart_on_postgres: DATABASE_URL not set");
        return;
    };

    // Deterministic start: clear any rows from a prior run on this DB.
    let pool = db::connect(&url).await.expect("connect pg");
    db::migrate(&pool).await.expect("migrate");
    sqlx::query("TRUNCATE network, invite, device")
        .execute(&pool)
        .await
        .expect("truncate");
    drop(pool);

    // --- Phase 1: run the coordination loop against PG via the HTTP router ---
    let (net_id, d1_id, d2_id, code) = {
        let store = Arc::new(SqlStore::connect(&url).await.expect("connect store"));
        let app = sql_router(store);

        let resp = app
            .clone()
            .oneshot(post("/api/v1/networks", json!({"name": "home"})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let net_id = body_json(resp).await["id"].as_str().unwrap().to_string();

        let resp = app
            .clone()
            .oneshot(post(
                &format!("/api/v1/networks/{net_id}/invites"),
                json!({"max_uses": 5}),
            ))
            .await
            .unwrap();
        let code = body_json(resp).await["code"].as_str().unwrap().to_string();

        let resp = enroll_pop(&app, &code, "a", 1).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let d1 = body_json(resp).await;
        assert_eq!(
            d1["address_v4"], "100.72.16.100",
            "first device gets .100 from DB-derived IPAM"
        );
        let d1_id = d1["id"].as_str().unwrap().to_string();

        let resp = enroll_pop(&app, &code, "b", 2).await;
        let d2_id = body_json(resp).await["id"].as_str().unwrap().to_string();

        // revoke d2
        let resp = app
            .clone()
            .oneshot(del(&format!("/api/v1/devices/{d2_id}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        (net_id, d1_id, d2_id, code)
    }; // <-- store + pool dropped here: simulates a full control-server shutdown

    // --- Phase 2: fresh connection to the SAME database (a "restart") ---
    let store2 = Arc::new(SqlStore::connect(&url).await.expect("reconnect store"));
    let app2 = sql_router(store2);

    // network survived
    let resp = app2.clone().oneshot(get("/api/v1/networks")).await.unwrap();
    let nets = body_json(resp).await;
    assert_eq!(nets.as_array().unwrap().len(), 1, "network persisted across restart");
    assert_eq!(nets[0]["id"], net_id);

    // d1 survived, still active, still serves its config (peers read back from DB)
    let resp = app2
        .clone()
        .oneshot(get(&format!("/api/v1/devices/{d1_id}/config")))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "active device config served after restart"
    );
    let cfg = body_json(resp).await;
    assert_eq!(cfg["address_v4"], "100.72.16.100");

    // d2 was revoked before the restart → still cut off after it
    let resp = app2
        .oneshot(get(&format!("/api/v1/devices/{d2_id}/config")))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "revocation persisted across restart"
    );

    // direct DB read-back: invite use-count was incremented and durable
    let pool = db::connect(&url).await.unwrap();
    let inv = db::get_invite(&pool, &code).await.unwrap().expect("invite persisted");
    assert_eq!(inv.uses, 2, "both enrollments counted, durably");
    let devs = db::list_devices(&pool, &net_id).await.unwrap();
    assert_eq!(devs.len(), 2, "both devices persisted (one active, one revoked)");

    eprintln!("OK: full coordination state durable across a simulated restart on PostgreSQL");
}
