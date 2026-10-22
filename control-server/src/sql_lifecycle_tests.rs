// SPDX-License-Identifier: BSD-3-Clause
use super::*;

#[tokio::test]
async fn failed_network_cascade_rolls_back_tokens_routes_invites_and_epoch() {
    let s = SqlStore::connect("sqlite::memory:").await.unwrap();
    let net = s.create_network("rollback").await.unwrap();
    let inv = s.create_invite(&net.id, None, None).await.unwrap();
    let (dev, token) = s.enroll(&inv.code, "device", &hex::encode([41;32]), 0).await.unwrap();
    s.advertise_route(&dev.id, "10.1.0.0/24").await.unwrap();
    s.report_stats(&dev.id, 1, 2, "[]", 0).await.unwrap();
    let mut watch = s.subscribe(&net.id);
    let before = s.device_config(&dev.id).await.unwrap().config_epoch;
    sqlx::query("CREATE TRIGGER fail_network_delete BEFORE DELETE ON network BEGIN SELECT RAISE(ABORT, 'injected cascade failure'); END")
        .execute(&s.pool).await.unwrap();
    assert!(s.delete_network(&net.id).await.is_err());
    assert_eq!(s.device_token(&dev.id).await.unwrap(), Some(token));
    assert_eq!(s.device_config(&dev.id).await.unwrap().config_epoch, before);
    assert_eq!(s.list_invites(&net.id).await.unwrap().len(), 1);
    assert_eq!(s.list_device_routes(&dev.id).await.unwrap().len(), 1);
    assert!(s.device_stats(&dev.id).await.unwrap().is_some());
    assert!(!watch.has_changed().unwrap());
    sqlx::query("DROP TRIGGER fail_network_delete").execute(&s.pool).await.unwrap();
    s.delete_network(&net.id).await.unwrap();
    watch.changed().await.unwrap();
    assert_eq!(*watch.borrow(), before + 1);
    assert!(watch.changed().await.is_err());
}

#[tokio::test]
async fn inactive_legacy_token_cannot_authenticate_even_if_not_cleared() {
    let s = SqlStore::connect("sqlite::memory:").await.unwrap();
    let net = s.create_network("legacy").await.unwrap();
    let inv = s.create_invite(&net.id, None, None).await.unwrap();
    let (dev, token) = s.enroll(&inv.code, "device", &hex::encode([42;32]), 0).await.unwrap();
    sqlx::query("UPDATE device SET status = 'revoked' WHERE id = $1").bind(&dev.id).execute(&s.pool).await.unwrap();
    assert!(s.device_token(&dev.id).await.unwrap().is_none());
    assert!(s.token_network(&token).await.unwrap().is_none());
    assert!(!s.has_device_token(&token).await.unwrap());
}

#[tokio::test]
async fn enrollment_racing_network_deletion_never_leaves_a_valid_token() {
    let owner = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", owner.path().join("race.db").display());
    let s = SqlStore::connect(&url).await.unwrap();
    let other = SqlStore::connect(&url).await.unwrap();
    let net = s.create_network("race").await.unwrap();
    let inv = s.create_invite(&net.id, None, None).await.unwrap();
    let key = hex::encode([43;32]);
    let (enroll, deletion) = tokio::join!(s.enroll(&inv.code, "race", &key, 0), other.delete_network(&net.id));
    deletion.unwrap();
    if let Ok((device, _)) = enroll { assert!(s.device_token(&device.id).await.unwrap().is_none()); }
    assert!(s.list_invites(&net.id).await.unwrap().is_empty());
    assert!(s.enroll(&inv.code, "again", &key, 0).await.is_err());
}

#[tokio::test]
async fn account_lookup_failure_returns_server_error_and_does_not_destroy_session() {
    use axum::{body::Body, http::{Request, StatusCode}};
    use tower::ServiceExt;
    use http_body_util::BodyExt;
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    let s = std::sync::Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    let hash = Argon2::default().hash_password(b"password", &SaltString::encode_b64(b"lookup-failure").unwrap()).unwrap().to_string();
    s.create_admin("admin", &hash, 0).await.unwrap();
    let app = crate::sql_router(s.clone());
    let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/v1/admin/login")
        .header("content-type", "application/json").body(Body::from(r#"{"username":"admin","password":"password"}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let token = body["token"].as_str().unwrap();
    let me = || Request::builder().uri("/api/v1/admin/me").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap();
    sqlx::query("ALTER TABLE admin RENAME TO admin_unavailable").execute(&s.pool).await.unwrap();
    assert_eq!(app.clone().oneshot(me()).await.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);
    sqlx::query("ALTER TABLE admin_unavailable RENAME TO admin").execute(&s.pool).await.unwrap();
    assert_eq!(app.oneshot(me()).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn hot_device_writes_do_not_update_entity_sequence() {
    let s = SqlStore::connect("sqlite::memory:").await.unwrap();
    let net = s.create_network("hot-writes").await.unwrap();
    let invite = s.create_invite(&net.id, None, None).await.unwrap();
    let (device, _) = s.enroll(&invite.code, "device", &hex::encode([44;32]), 0).await.unwrap();
    let epoch = s.device_config(&device.id).await.unwrap().config_epoch;
    // Even a no-op UPDATE used only for locking fires this trigger. SQLite's
    // database-wide writer lock cannot demonstrate PostgreSQL row concurrency.
    sqlx::query("CREATE TRIGGER forbid_entity_update BEFORE UPDATE ON control_sequence BEGIN SELECT RAISE(ABORT, 'hot path touched entity sequence'); END")
        .execute(&s.pool).await.unwrap();
    let stats = s.report_stats(&device.id, 10, 20, "[]", 1).await;
    let endpoints = s.set_endpoints(&device.id, &["127.0.0.1:1234".into()]).await;
    assert!(stats.is_ok(), "stats must not update the entity sequence: {stats:?}");
    assert!(endpoints.is_ok(), "endpoints must not update the entity sequence: {endpoints:?}");
    assert_eq!(s.device_stats(&device.id).await.unwrap(), Some((10, 20, "[]".into(), 1)));
    assert_eq!(db::get_device_endpoints(&s.pool, &device.id).await.unwrap(), ["127.0.0.1:1234"]);
    assert_eq!(s.device_config(&device.id).await.unwrap().config_epoch, epoch + 1);
    // Verify the guard is live and lifecycle operations still use that lock.
    let error = s.delete_network(&net.id).await.unwrap_err();
    assert!(error.to_string().contains("hot path touched entity sequence"));
}

#[tokio::test]
async fn stats_racing_network_deletion_across_stores_leave_no_stats_row() {
    let owner = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", owner.path().join("stats-race.db").display());
    let writer = SqlStore::connect(&url).await.unwrap();
    let deleter = SqlStore::connect(&url).await.unwrap();
    for deletion_first in [false, true] {
        let net = writer.create_network("stats-race").await.unwrap();
        let invite = writer.create_invite(&net.id, None, None).await.unwrap();
        let (device, _) = writer.enroll(&invite.code, "device", &hex::encode([45;32]), 0).await.unwrap();
        writer.report_stats(&device.id, 1, 2, "[]", 0).await.unwrap();
        let (write, delete) = if deletion_first {
            let (delete, write) = tokio::join!(deleter.delete_network(&net.id), writer.report_stats(&device.id, 3, 4, "[]", 1));
            (write, delete)
        } else {
            tokio::join!(writer.report_stats(&device.id, 3, 4, "[]", 1), deleter.delete_network(&net.id))
        };
        delete.unwrap();
        assert!(matches!(write, Ok(()) | Err(SqlStoreError::DeviceNotFound)), "{write:?}");
        assert!(writer.device_stats(&device.id).await.unwrap().is_none());
        assert!(matches!(writer.report_stats(&device.id, 5, 6, "[]", 2).await, Err(SqlStoreError::DeviceNotFound)));
        assert!(writer.device_stats(&device.id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn hot_device_writes_reject_missing_revoked_and_networkless_devices() {
    let s = SqlStore::connect("sqlite::memory:").await.unwrap();
    let net = s.create_network("active-check").await.unwrap();
    let invite = s.create_invite(&net.id, None, None).await.unwrap();
    let (revoked, _) = s.enroll(&invite.code, "revoked", &hex::encode([46;32]), 0).await.unwrap();
    let (orphan, _) = s.enroll(&invite.code, "orphan", &hex::encode([47;32]), 0).await.unwrap();
    s.revoke_device(&revoked.id).await.unwrap();
    // Deliberately bypass the cascade to model legacy inconsistent data.
    sqlx::query("DELETE FROM network WHERE id = $1").bind(&net.id).execute(&s.pool).await.unwrap();
    for id in ["missing", &revoked.id, &orphan.id] {
        assert!(matches!(s.report_stats(id, 1, 2, "[]", 0).await, Err(SqlStoreError::DeviceNotFound)), "stats {id}");
        assert!(matches!(s.set_endpoints(id, &["127.0.0.1:1234".into()]).await, Err(SqlStoreError::DeviceNotFound)), "endpoints {id}");
        assert!(s.device_stats(id).await.unwrap().is_none());
        assert!(db::get_device_endpoints(&s.pool, id).await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn file_sqlite_pool_settings_and_writer_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}?mode=rwc", dir.path().join("busy.db").display());
    let store = SqlStore::connect(&url).await.unwrap();
    let other = SqlStore::connect(&url).await.unwrap();
    // Hold all connections at once, including newly created pool connections.
    let mut connections = Vec::new();
    for _ in 0..5 { connections.push(store.pool.acquire().await.unwrap()); }
    for conn in &mut connections {
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(&mut **conn).await.unwrap();
        let busy: i64 = sqlx::query_scalar("PRAGMA busy_timeout").fetch_one(&mut **conn).await.unwrap();
        let sync: i64 = sqlx::query_scalar("PRAGMA synchronous").fetch_one(&mut **conn).await.unwrap();
        assert_eq!(mode, "wal"); assert_eq!(busy, 5000); assert_eq!(sync, 1);
    }
    drop(connections);
    let mut first = crate::integrity::begin(&store.pool).await.unwrap();
    sqlx::query("UPDATE control_sequence SET value = 700 WHERE name = 'entity'").execute(&mut *first).await.unwrap();
    let waiter = tokio::spawn(async move {
        let mut second = crate::integrity::begin(&other.pool).await.unwrap();
        let value: i64 = sqlx::query_scalar("SELECT value FROM control_sequence WHERE name = 'entity'")
            .fetch_one(&mut *second).await.unwrap();
        assert_eq!(value, 700, "writer must read after obtaining the reservation");
        second.commit().await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!waiter.is_finished(), "writer must wait instead of failing an upgrade");
    // WAL allows a pooled reader to proceed while the write reservation is held.
    let value: i64 = sqlx::query_scalar("SELECT value FROM control_sequence WHERE name = 'entity'")
        .fetch_one(&store.pool).await.unwrap();
    assert_ne!(value, 700);
    first.commit().await.unwrap();
    waiter.await.unwrap();
    store.pool.close().await;
}

#[tokio::test]
async fn http_500_logs_database_root_cause_without_changing_response_body() {
    use axum::{body::Body, http::{Request, StatusCode}};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use std::io::{Read, Seek};
    let store = std::sync::Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    let net = store.create_network("error-log").await.unwrap();
    let invite = store.create_invite(&net.id, None, None).await.unwrap();
    let (device, token) = store.enroll(&invite.code, "fixture", &hex::encode([54;32]), 0).await.unwrap();
    let app = crate::sql_router(store.clone());
    let capture = tempfile::tempfile().unwrap();
    let mut reader = capture.try_clone().unwrap();
    let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false)
        .with_max_level(tracing::Level::ERROR).with_writer(move || capture.try_clone().unwrap()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // The first failure passes sql_status; the second fails in device auth.
    for table in ["route", "device"] {
        sqlx::query(&format!("DROP TABLE {table}")).execute(&store.pool).await.unwrap();
        let response = app.clone().oneshot(Request::builder().uri(format!("/api/v1/devices/{}/config", device.id))
            .header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
    }
    reader.rewind().unwrap();
    let mut output = String::new(); reader.read_to_string(&mut output).unwrap();
    assert_eq!(output.matches("ERROR").count(), 2, "{output}");
    assert!(output.contains("no such table: route"), "{output}");
    assert!(output.contains("no such table: device"), "{output}");
    assert!(!output.contains(&token), "bearer credentials must not be logged");
}

#[tokio::test]
async fn pool_acquire_timeout_is_visible_and_recovers_after_release() {
    use axum::{body::Body, http::{Request, StatusCode}};
    use tower::ServiceExt;
    use std::io::{Read, Seek};
    let store = std::sync::Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    let app = crate::sql_router(store.clone());
    let held = store.pool.acquire().await.unwrap();
    let capture = tempfile::tempfile().unwrap();
    let mut reader = capture.try_clone().unwrap();
    let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false)
        .with_max_level(tracing::Level::ERROR).with_writer(move || capture.try_clone().unwrap()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let started = std::time::Instant::now();
    let response = tokio::time::timeout(std::time::Duration::from_secs(7), app.clone().oneshot(Request::builder()
        .uri("/api/v1/devices/missing/config").header("authorization", "Bearer private-fixture")
        .body(Body::empty()).unwrap())).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(started.elapsed() >= std::time::Duration::from_secs(5));
    reader.rewind().unwrap();
    let mut output = String::new(); reader.read_to_string(&mut output).unwrap();
    assert_eq!(output.matches("ERROR").count(), 1, "{output}");
    assert!(output.contains("pool acquire timed out"), "{output}");
    assert!(!output.contains("private-fixture"));
    drop(held);
    tokio::time::timeout(std::time::Duration::from_secs(1), store.list_networks()).await.unwrap().unwrap();
    let response = app.oneshot(Request::builder().uri("/api/v1/devices/missing/config")
        .header("authorization", "Bearer private-fixture").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    store.pool.close().await;
}
