// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use axum::{Router, body::Body, http::{Request, StatusCode}, response::Response};
use std::{sync::Arc, time::{Duration, Instant}, io::{Read, Seek}};
use tower::ServiceExt;

struct Fixture {
    _dir: tempfile::TempDir,
    store: Arc<SqlStore>,
    network: Network,
    device: Device,
    token: String,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite:{}?mode=rwc", dir.path().join("contention.db").display());
        let store = Arc::new(SqlStore::connect(&url).await.unwrap());
        let network = store.create_network("contention").await.unwrap();
        let invite = store.create_invite(&network.id, None, None).await.unwrap();
        let (device, token) = store.enroll(&invite.code, "writer", &hex::encode([58;32]), 0).await.unwrap();
        Self { _dir: dir, store, network, device, token }
    }

    async fn short_busy_timeout(&self) {
        // Configure every connection without process-global environment mutation.
        let mut connections = Vec::new();
        for _ in 0..5 { connections.push(self.store.pool.acquire().await.unwrap()); }
        for conn in &mut connections {
            sqlx::query("PRAGMA busy_timeout = 20").execute(&mut **conn).await.unwrap();
        }
    }

    async fn hold_writer(&self) -> sqlx::Transaction<'static, sqlx::Any> {
        let mut tx = self.store.pool.begin().await.unwrap();
        sqlx::query("UPDATE control_sequence SET value = value WHERE name = 'entity'").execute(&mut *tx).await.unwrap();
        tx
    }

    async fn request(&self, app: &Router, suffix: &str, body: Option<&str>) -> Response {
        let request = Request::builder().method(if body.is_some() { "POST" } else { "GET" })
            .uri(format!("/api/v1/devices/{}/{}", self.device.id, suffix))
            .header("authorization", format!("Bearer {}", self.token)).header("content-type", "application/json")
            .body(Body::from(body.unwrap_or("").to_owned())).unwrap();
        tokio::time::timeout(Duration::from_secs(12), app.clone().oneshot(request)).await.unwrap().unwrap()
    }
}

#[tokio::test]
async fn eight_second_writer_allows_config_reads_and_stats_endpoints_recover_without_500() {
    let f = Fixture::new().await;
    let held = f.hold_writer().await;
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(8)).await;
        held.commit().await.unwrap();
    });
    let app = crate::sql_router(f.store.clone());
    let started = Instant::now();
    let (stats, endpoints, config) = tokio::join!(
        f.request(&app, "stats", Some(r#"{"rx_bytes":41,"tx_bytes":42,"peers":[]}"#)),
        f.request(&app, "endpoints", Some(r#"{"endpoints":["192.0.2.1:2345"]}"#)),
        async { tokio::time::timeout(Duration::from_secs(2), f.request(&app, "config", None)).await.unwrap() },
    );
    assert_eq!(config.status(), StatusCode::OK, "WAL config reads must not wait for a write lock");
    assert_eq!(stats.status(), StatusCode::NO_CONTENT);
    assert_eq!(endpoints.status(), StatusCode::NO_CONTENT);
    assert!(started.elapsed() >= Duration::from_secs(8));
    release.await.unwrap();
    assert_eq!(f.store.device_stats(&f.device.id).await.unwrap().unwrap().0, 41);
    assert_eq!(db::get_device_endpoints(&f.store.pool, &f.device.id).await.unwrap(), ["192.0.2.1:2345"]);
    eprintln!("8-second SQLite writer: config=200, stats=204, endpoints=204; elapsed={:?}", started.elapsed());
}

#[tokio::test]
async fn exhausted_busy_transactions_return_503_retry_after_warn_and_preserve_state() {
    let f = Fixture::new().await;
    f.store.report_stats(&f.device.id, 7, 8, "[]", 0).await.unwrap();
    let epoch = f.store.device_config(&f.device.id).await.unwrap().config_epoch;
    f.short_busy_timeout().await;
    let held = f.hold_writer().await;
    let capture = tempfile::tempfile().unwrap(); let mut reader = capture.try_clone().unwrap();
    let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false)
        .with_max_level(tracing::Level::WARN).with_writer(move || capture.try_clone().unwrap()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let app = crate::sql_router(f.store.clone());
    let (stats, endpoints, invite) = tokio::join!(
        f.request(&app, "stats", Some(r#"{"rx_bytes":99,"tx_bytes":100,"peers":[]}"#)),
        f.request(&app, "endpoints", Some(r#"{"endpoints":["192.0.2.1:7777"]}"#)),
        f.store.create_invite(&f.network.id, None, None),
    );
    for response in [stats, endpoints] {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get("retry-after").unwrap(), "1");
    }
    assert!(matches!(invite, Err(SqlStoreError::Db(ref error)) if crate::contention::sqlite_busy(error)));
    reader.rewind().unwrap(); let mut output = String::new(); reader.read_to_string(&mut output).unwrap();
    assert_eq!(output.matches("exhausted retries").count(), 3, "{output}");
    assert_eq!(output.matches("retrying transaction").count(), 6, "exactly three attempts per operation: {output}");
    assert!(!output.contains("ERROR"), "expected contention is WARN: {output}");
    assert!(!output.contains(&f.token));
    held.rollback().await.unwrap();
    assert_eq!(f.store.device_stats(&f.device.id).await.unwrap().unwrap().0, 7);
    assert_eq!(f.store.device_config(&f.device.id).await.unwrap().config_epoch, epoch);
    assert!(db::get_device_endpoints(&f.store.pool, &f.device.id).await.unwrap().is_empty());
    assert_eq!(f.store.list_invites(&f.network.id).await.unwrap().len(), 1);
    f.store.report_stats(&f.device.id, 99, 100, "[]", 1).await.unwrap();
    f.store.set_endpoints(&f.device.id, &["192.0.2.1:7777".into()]).await.unwrap();
    assert_eq!(f.store.device_config(&f.device.id).await.unwrap().config_epoch, epoch + 1);
}

#[tokio::test]
async fn busy_transaction_retries_succeed_after_lock_release() {
    let f = Fixture::new().await;
    f.short_busy_timeout().await;
    let held = f.hold_writer().await;
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        held.commit().await.unwrap();
    });
    let addresses = ["192.0.2.2:4567".into()];
    let (stats, endpoints, invite) = tokio::join!(
        f.store.report_stats(&f.device.id, 3, 4, "[]", 0),
        f.store.set_endpoints(&f.device.id, &addresses),
        f.store.create_invite(&f.network.id, None, None),
    );
    stats.unwrap(); endpoints.unwrap(); invite.unwrap(); release.await.unwrap();
    assert_eq!(f.store.list_invites(&f.network.id).await.unwrap().len(), 2);
}

#[tokio::test]
async fn retry_drops_failed_transactions_before_reusing_connection_and_never_retries_other_errors() {
    let f = Fixture::new().await;
    f.short_busy_timeout().await;
    let held = f.hold_writer().await;
    let mut errors = Vec::new();
    for _ in 0..3 {
        errors.push(sqlx::query("UPDATE control_sequence SET value = value").execute(&f.store.pool).await.unwrap_err());
    }
    held.rollback().await.unwrap();
    let pool = db::connect("sqlite::memory:").await.unwrap();
    sqlx::query("CREATE TABLE rollback_probe (value BIGINT)").execute(&pool).await.unwrap();
    let result = crate::contention::retry("rollback_probe", false, || {
        let error = errors.remove(0); let pool = &pool;
        async move {
            let mut tx = pool.begin().await?;
            sqlx::query("INSERT INTO rollback_probe VALUES (1)").execute(&mut *tx).await?;
            Err::<(), _>(SqlStoreError::Db(error))
        }
    }).await;
    assert!(result.is_err()); assert!(errors.is_empty());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rollback_probe").fetch_one(&pool).await.unwrap();
    assert_eq!(count, 0);
    let mut attempts = 0;
    let result = crate::contention::retry("nonbusy", true, || {
        attempts += 1;
        std::future::ready(Err::<(), _>(SqlStoreError::Db(sqlx::Error::Protocol("not busy".into()))))
    }).await;
    assert!(result.is_err()); assert_eq!(attempts, 1);
}

#[tokio::test]
async fn wal_autocheckpoint_recycles_frames_on_the_writer_connection() {
    let f = Fixture::new().await;
    let mut conn = f.store.pool.acquire().await.unwrap();
    let configured: i64 = sqlx::query_scalar("PRAGMA wal_autocheckpoint").fetch_one(&mut *conn).await.unwrap();
    assert_eq!(configured, 1000);
    sqlx::query("CREATE TABLE checkpoint_probe (value BLOB)").execute(&mut *conn).await.unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&mut *conn).await.unwrap();
    // More than 1000 pages of separate autocommit writes must cause a checkpoint.
    for _ in 0..200 {
        sqlx::query("INSERT INTO checkpoint_probe VALUES (zeroblob(32768))").execute(&mut *conn).await.unwrap();
    }
    let row = sqlx::query("PRAGMA wal_checkpoint(PASSIVE)").fetch_one(&mut *conn).await.unwrap();
    let frames: i64 = row.get(1); let checkpointed: i64 = row.get(2);
    assert!(frames > 0 && frames < 1000, "automatic checkpoints must reset the frame count: {frames}");
    assert_eq!(frames, checkpointed);
}
