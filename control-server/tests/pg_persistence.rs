// SPDX-License-Identifier: BSD-3-Clause
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
    Request::builder().uri(uri).header("authorization", "Bearer test-pg").body(Body::empty()).unwrap()
}
fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", "Bearer test-pg")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
fn del(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .header("authorization", "Bearer test-pg")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}
async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Prepare a distinct proof before releasing concurrent enrollment requests.
async fn enroll_request(app: &axum::Router, code: &str, name: &str, seed: u8) -> Request<Body> {
    use fp_crypto::x25519::{PublicKey, StaticSecret};
    let sk = StaticSecret::from([seed; 32]);
    let pub_hex = hex::encode(PublicKey::from(&sk).to_bytes());
    let resp = app
        .clone()
        .oneshot(post("/api/v1/enroll/challenge", json!({ "wg_public_key": pub_hex })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "PoP challenge");
    let chal = body_json(resp).await;
    let server_pub: [u8; 32] = hex::decode(chal["server_pub"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let proof = hex::encode(sk.diffie_hellman(&PublicKey::from(server_pub)).to_bytes());
    post("/api/v1/enroll", json!({
        "invite_code": code, "name": name, "wg_public_key": pub_hex,
        "challenge_id": chal["challenge_id"].as_str().unwrap(), "proof": proof,
    }))
}

async fn enroll_pop(app: &axum::Router, code: &str, name: &str, seed: u8) -> axum::response::Response {
    app.clone().oneshot(enroll_request(app, code, name, seed).await).await.unwrap()
}

// Set the master bearer before the isolated test process starts threads. Each
// case uses its own schema; never truncate tables in the supplied database.
fn run_postgres_case(name: &str) {
    let Some(url) = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty()) else {
        eprintln!("SKIP {name}: DATABASE_URL not set"); return;
    };
    assert!(url.starts_with("postgres://") || url.starts_with("postgresql://"), "DATABASE_URL must select PostgreSQL");
    if std::env::var("FLUXPEER_TEST_PG_CHILD").as_deref() != Ok(name) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("FLUXPEER_TEST_PG_CHILD", name).env("FLUXPEER_ADMIN_PASSWORD", "test-pg")
            .output().unwrap();
        eprint!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success(), "PostgreSQL child failed"); return;
    }
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(async {
        use futures_util::FutureExt;
        use sqlx::ConnectOptions;
        let base = db::connect(&url).await.expect("connect PostgreSQL fixture");
        let schema = format!("fpe_test_{}_{}", std::process::id(), rand::random::<u64>());
        sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&base).await.unwrap();
        let mut scoped = url.parse::<sqlx::any::AnyConnectOptions>().unwrap().to_url_lossy();
        scoped.query_pairs_mut().append_pair("options[search_path]", &schema);
        let result = std::panic::AssertUnwindSafe(async {
            tokio::time::timeout(std::time::Duration::from_secs(90), async {
                let probe = db::connect(scoped.as_str()).await.unwrap();
                let actual: String = sqlx::query_scalar("SELECT current_schema()::text").fetch_one(&probe).await.unwrap();
                probe.close().await;
                assert_eq!(actual, schema, "fixture must not touch the public schema");
                match name {
                    "persistence_survives_restart_on_postgres" => persistence_restart(scoped.as_str()).await,
                    "concurrent_enroll_single_use_on_postgres" => concurrent_enroll(scoped.as_str()).await,
                    "migration_twice_on_postgres" => migration_twice(scoped.as_str()).await,
                    _ => panic!("unknown test case"),
                }
            }).await.expect("PostgreSQL case timed out");
        }).catch_unwind().await;
        // Cleanup also runs after an assertion panic. Only our random schema is removed.
        let cleanup = sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&base).await;
        base.close().await;
        cleanup.expect("remove PostgreSQL test schema");
        if let Err(panic) = result { std::panic::resume_unwind(panic); }
    });
}

#[test]
fn persistence_survives_restart_on_postgres() { run_postgres_case("persistence_survives_restart_on_postgres"); }
#[test]
fn concurrent_enroll_single_use_on_postgres() { run_postgres_case("concurrent_enroll_single_use_on_postgres"); }
#[test]
fn migration_twice_on_postgres() { run_postgres_case("migration_twice_on_postgres"); }

async fn persistence_restart(url: &str) {
    // --- Phase 1: run the coordination loop against PG via the HTTP router ---
    let (net_id, d1_id, d2_id, code) = {
        let store = Arc::new(SqlStore::connect(url).await.expect("connect store"));
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
    let store2 = Arc::new(SqlStore::connect(url).await.expect("reconnect store"));
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
    let pool = db::connect(url).await.unwrap();
    let inv = db::get_invite(&pool, &code).await.unwrap().expect("invite persisted");
    assert_eq!(inv.uses, 2, "both enrollments counted, durably");
    let devs = db::list_devices(&pool, &net_id).await.unwrap();
    assert_eq!(devs.len(), 2, "both devices persisted (one active, one revoked)");

    eprintln!("OK: full coordination state durable across a simulated restart on PostgreSQL");
}

async fn concurrent_enroll(url: &str) {
    let first = Arc::new(SqlStore::connect(url).await.unwrap());
    let second = Arc::new(SqlStore::connect(url).await.unwrap());
    let network = first.create_network("single-use-race").await.unwrap();
    let invite = first.create_invite(&network.id, None, Some(1)).await.unwrap();
    let apps = [sql_router(first), sql_router(second)];
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut jobs = tokio::task::JoinSet::new();
    for seed in 10..18u8 {
        let app = apps[usize::from(seed) % apps.len()].clone();
        let code = invite.code.clone(); let ready = barrier.clone();
        jobs.spawn(async move {
            let request = enroll_request(&app, &code, "concurrent", seed).await;
            ready.wait().await;
            app.oneshot(request).await.unwrap().status()
        });
    }
    let mut created = 0;
    while let Some(result) = jobs.join_next().await {
        let status = result.unwrap();
        if status == StatusCode::CREATED { created += 1; }
        else { assert_eq!(status, StatusCode::FORBIDDEN, "exhausted invitation must reject without a server error"); }
    }
    assert_eq!(created, 1);
    let pool = db::connect(url).await.unwrap();
    assert_eq!(db::get_invite(&pool, &invite.code).await.unwrap().unwrap().uses, 1);
    let devices = db::list_devices(&pool, &network.id).await.unwrap();
    assert_eq!(devices.len(), 1, "losing enrollments leave no device or address behind");
    assert!(devices[0].address_v4.is_some());
    pool.close().await;
}

async fn migration_twice(url: &str) {
    use base64::Engine;
    use sqlx::Row;
    let pool = db::connect(url).await.unwrap();
    // Pre-migration schema with a base64 key exercises actual normalization and
    // index creation, not merely a second migration of an empty database.
    sqlx::query("CREATE TABLE network (id TEXT PRIMARY KEY, name TEXT NOT NULL, ipv4_pool TEXT NOT NULL, ipv6_ula TEXT NOT NULL, config_epoch BIGINT NOT NULL)")
        .execute(&pool).await.unwrap();
    sqlx::query("CREATE TABLE device (id TEXT PRIMARY KEY, network_id TEXT NOT NULL, name TEXT NOT NULL, wg_public_key TEXT NOT NULL, address_v4 TEXT, address_v6 TEXT, status TEXT NOT NULL)")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO network VALUES ('net-90', 'legacy', '100.72.16.0/24', 'fd72::/64', 1)").execute(&pool).await.unwrap();
    let key = base64::engine::general_purpose::STANDARD.encode([0x11; 32]);
    sqlx::query("INSERT INTO device VALUES ('dev-91', 'net-90', 'legacy', $1, '100.72.16.100', NULL, 'active')")
        .bind(key).execute(&pool).await.unwrap();
    db::migrate(&pool).await.unwrap();
    let epoch = db::get_network(&pool, "net-90").await.unwrap().unwrap().config_epoch;
    assert_eq!(epoch, 2, "normalizing the active legacy key bumps the epoch once");
    let indexes = || sqlx::query("SELECT indexname::text AS indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() ORDER BY indexname");
    let before: Vec<(String, String)> = indexes().fetch_all(&pool).await.unwrap().iter()
        .map(|row| (row.get("indexname"), row.get("indexdef"))).collect();
    db::migrate(&pool).await.unwrap();
    let after: Vec<(String, String)> = indexes().fetch_all(&pool).await.unwrap().iter()
        .map(|row| (row.get("indexname"), row.get("indexdef"))).collect();
    assert_eq!(before, after);
    for index in ["device_network_active_key", "device_network_active_v4"] {
        assert!(after.iter().any(|(name, definition)| name == index && definition.contains("UNIQUE") && definition.contains("WHERE") && definition.contains("active")));
    }
    assert_eq!(db::get_network(&pool, "net-90").await.unwrap().unwrap().config_epoch, epoch);
    assert_eq!(db::get_device(&pool, "dev-91").await.unwrap().unwrap().wg_public_key, "11".repeat(32));
    let high: i64 = sqlx::query("SELECT value FROM control_sequence WHERE name = 'entity'").fetch_one(&pool).await.unwrap().get("value");
    assert!(high >= 91);
    pool.close().await;
}
