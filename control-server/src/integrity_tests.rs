// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use std::sync::Arc;
use base64::{Engine, engine::general_purpose::STANDARD};
use sqlx::Row;

async fn fixture() -> (tempfile::TempDir, String, Arc<SqlStore>) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("control.db").display());
    let store = Arc::new(SqlStore::connect(&url).await.unwrap());
    (dir, url, store)
}

fn key(seed: u8) -> String { hex::encode([seed; 32]) }

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_use_invite_is_atomic_across_stores_and_connections() {
    let (_dir, url, a) = fixture().await;
    let b = Arc::new(SqlStore::connect(&url).await.unwrap());
    let net = a.create_network("race").await.unwrap();
    let invite = a.create_invite(&net.id, None, Some(1)).await.unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(12));
    let mut jobs = Vec::new();
    for n in 0..12 {
        let store = if n % 2 == 0 { a.clone() } else { b.clone() };
        let code = invite.code.clone();
        let barrier = barrier.clone();
        jobs.push(tokio::spawn(async move {
            barrier.wait().await;
            store.enroll(&code, "race", &key(n), 100).await
        }));
    }
    let mut successes = 0;
    for job in jobs {
        match job.await.unwrap() {
            Ok(_) => successes += 1,
            Err(SqlStoreError::InvalidInvite) => {}
            Err(error) => panic!("unexpected race failure: {error}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(a.list_devices(&net.id).await.unwrap().len(), 1);
    assert_eq!(db::get_invite(&a.pool, &invite.code).await.unwrap().unwrap().uses, 1);
    assert_eq!(db::get_network(&a.pool, &net.id).await.unwrap().unwrap().config_epoch, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_enrolls_using_different_invites_allocate_unique_addresses() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("ipam").await.unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut jobs = Vec::new();
    for n in 0..16 {
        let invite = store.create_invite(&net.id, None, Some(1)).await.unwrap();
        let store = store.clone();
        let barrier = barrier.clone();
        jobs.push(tokio::spawn(async move {
            barrier.wait().await;
            store.enroll(&invite.code, "device", &key(n), 100).await.unwrap().0
        }));
    }
    let mut ips = HashSet::new();
    let mut ids = HashSet::new();
    for job in jobs {
        let d = job.await.unwrap();
        assert!(ips.insert(d.address_v4.unwrap()));
        assert!(ids.insert(d.id));
    }
    assert_eq!(ips.len(), 16);
}

#[tokio::test]
async fn repeat_key_preserves_identity_and_rotates_token_without_consuming_invite() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("repeat").await.unwrap();
    let invite = store.create_invite(&net.id, Some(200), Some(1)).await.unwrap();
    let (first, old_token) = store.enroll(&invite.code, "original", &key(0xab).to_uppercase(), 100).await.unwrap();
    let route = store.advertise_route(&first.id, "10.0.0.0/24").await.unwrap();
    let (again, new_token) = store.enroll(&invite.code, "ignored", &STANDARD.encode([0xab; 32]), 101).await.unwrap();
    assert_eq!(first, again);
    assert_eq!(again.wg_public_key, key(0xab));
    assert_ne!(old_token, new_token);
    assert_eq!(store.device_token(&first.id).await.unwrap(), Some(new_token.clone()));
    assert_eq!(store.list_device_routes(&first.id).await.unwrap(), vec![route]);
    assert_eq!(db::get_invite(&store.pool, &invite.code).await.unwrap().unwrap().uses, 1);
    assert!(matches!(store.enroll(&invite.code, "expired", &key(0xab), 200).await, Err(SqlStoreError::InvalidInvite)));
    store.revoke_device(&first.id).await.unwrap();
    assert!(matches!(store.enroll(&invite.code, "revoked", &key(0xab), 101).await, Err(SqlStoreError::InvalidInvite)));
    assert_eq!(store.device_token(&first.id).await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_same_key_enroll_is_one_device_with_one_current_token() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("repeat race").await.unwrap();
    let invite = store.create_invite(&net.id, None, Some(1)).await.unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut jobs = Vec::new();
    for n in 0..8 {
        let store = store.clone(); let code = invite.code.clone(); let barrier = barrier.clone();
        jobs.push(tokio::spawn(async move {
            barrier.wait().await;
            let public_key = if n % 2 == 0 { key(0xab) } else { STANDARD.encode([0xab; 32]) };
            store.enroll(&code, "repeat", &public_key, 100).await.unwrap()
        }));
    }
    let mut results = Vec::new();
    for job in jobs { results.push(job.await.unwrap()); }
    let device = &results[0].0;
    assert!(results.iter().all(|(d, _)| d == device));
    let current = store.device_token(&device.id).await.unwrap().unwrap();
    assert_eq!(results.iter().filter(|(_, token)| token == &current).count(), 1);
    assert_eq!(store.list_devices(&net.id).await.unwrap().len(), 1);
    assert_eq!(db::get_invite(&store.pool, &invite.code).await.unwrap().unwrap().uses, 1);
}

#[tokio::test]
async fn enrollment_failure_rolls_back_invite_device_token_epoch_and_sequence() {
    for trigger in [
        "CREATE TRIGGER fail BEFORE INSERT ON device BEGIN SELECT RAISE(ABORT, 'injected insert'); END",
        "CREATE TRIGGER fail BEFORE UPDATE OF auth_token ON device BEGIN SELECT RAISE(ABORT, 'injected token'); END",
        "CREATE TRIGGER fail BEFORE UPDATE OF config_epoch ON network BEGIN SELECT RAISE(ABORT, 'injected epoch'); END",
    ] {
        let (_dir, _url, store) = fixture().await;
        let net = store.create_network("rollback").await.unwrap();
        let invite = store.create_invite(&net.id, None, Some(1)).await.unwrap();
        let before: i64 = sqlx::query_scalar("SELECT value FROM control_sequence WHERE name = 'entity'").fetch_one(&store.pool).await.unwrap();
        sqlx::query(trigger).execute(&store.pool).await.unwrap();
        assert!(store.enroll(&invite.code, "fail", &key(1), 100).await.is_err());
        assert!(store.list_devices(&net.id).await.unwrap().is_empty());
        assert_eq!(db::get_invite(&store.pool, &invite.code).await.unwrap().unwrap().uses, 0);
        assert_eq!(db::get_network(&store.pool, &net.id).await.unwrap().unwrap().config_epoch, 0);
        let after: i64 = sqlx::query_scalar("SELECT value FROM control_sequence WHERE name = 'entity'").fetch_one(&store.pool).await.unwrap();
        assert_eq!(before, after);
        sqlx::query("DROP TRIGGER fail").execute(&store.pool).await.unwrap();
        store.enroll(&invite.code, "retry", &key(1), 100).await.unwrap();
    }
}

#[tokio::test]
async fn restart_recovers_relay_route_maximum_and_preserves_deleted_high_water_mark() {
    let (_dir, url, store) = fixture().await;
    let net = store.create_network("restart").await.unwrap();
    let invite = store.create_invite(&net.id, None, None).await.unwrap();
    let (device, _) = store.enroll(&invite.code, "device", &key(1), 100).await.unwrap();
    let relay = store.register_relay("test", "localhost:443", None, false, None, None).await.unwrap();
    let route = store.advertise_route(&device.id, "10.0.0.0/24").await.unwrap();
    // Simulate a legacy DB with sparse IDs and no persisted sequence.
    sqlx::query("UPDATE relay SET id = 'relay-900' WHERE id = $1").bind(&relay.id).execute(&store.pool).await.unwrap();
    sqlx::query("UPDATE route SET id = 'route-950' WHERE id = $1").bind(&route.id).execute(&store.pool).await.unwrap();
    sqlx::query("DROP TABLE control_sequence").execute(&store.pool).await.unwrap();
    store.pool.close().await;
    drop(store);
    let reopened = SqlStore::connect(&url).await.unwrap();
    let relay2 = reopened.register_relay("test", "localhost:444", None, false, None, None).await.unwrap();
    let route2 = reopened.advertise_route(&device.id, "10.1.0.0/24").await.unwrap();
    assert_eq!(relay2.id, "relay-951");
    assert_eq!(route2.id, "route-952");
    reopened.delete_route(&route2.id).await.unwrap();
    reopened.pool.close().await;
    drop(reopened);
    let reopened = SqlStore::connect(&url).await.unwrap();
    assert_eq!(reopened.advertise_route(&device.id, "10.2.0.0/24").await.unwrap().id, "route-953");
}

async fn legacy_rows(store: &SqlStore, net: &str, keys: &[String], addresses: &[Option<&str>]) {
    sqlx::query("DROP INDEX device_network_active_key").execute(&store.pool).await.unwrap();
    sqlx::query("DROP INDEX device_network_active_v4").execute(&store.pool).await.unwrap();
    for (i, (key, addr)) in keys.iter().zip(addresses).enumerate() {
        sqlx::query("INSERT INTO device (id, network_id, name, wg_public_key, address_v4, status) VALUES ($1,$2,'legacy',$3,$4,'active')")
            .bind(format!("dev-{}", i + 100)).bind(net).bind(key).bind(addr).execute(&store.pool).await.unwrap();
    }
}

#[tokio::test]
async fn migration_normalizes_legacy_keys_and_enforces_both_unique_indexes() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("legacy").await.unwrap();
    legacy_rows(&store, &net.id, &[STANDARD.encode([0xab; 32]), key(0xcd).to_uppercase()], &[Some("100.72.16.100"), None]).await;
    db::migrate(&store.pool).await.unwrap();
    db::migrate(&store.pool).await.unwrap();
    let devices = store.list_devices(&net.id).await.unwrap();
    assert_eq!(devices[0].wg_public_key, key(0xab));
    assert_eq!(devices[1].wg_public_key, key(0xcd));
    for (public_key, address) in [(key(0xab), None), (key(3), Some("100.72.16.100"))] {
        let error = sqlx::query("INSERT INTO device (id, network_id, name, wg_public_key, address_v4, status) VALUES ('dev-new',$1,'duplicate',$2,$3,'active')")
            .bind(&net.id).bind(public_key).bind(address).execute(&store.pool).await.unwrap_err();
        assert!(error.as_database_error().unwrap().is_unique_violation());
    }
}

#[tokio::test]
async fn migration_rejects_legacy_key_address_conflicts_and_bad_keys_without_data_loss() {
    for (keys, addresses, expected) in [
        (vec![STANDARD.encode([0xab; 32]), key(0xab)], vec![None, None], "duplicate public key"),
        (vec![STANDARD.encode([0xab; 32]), key(2)], vec![Some("100.72.16.100"), Some("100.72.16.100")], "duplicate IPv4"),
        (vec![STANDARD.encode([0xab; 32]), "bad-key".into()], vec![None, None], "invalid public key"),
    ] {
        let (_dir, _url, store) = fixture().await;
        let net = store.create_network("legacy conflict").await.unwrap();
        legacy_rows(&store, &net.id, &keys, &addresses).await;
        let before = store.list_devices(&net.id).await.unwrap();
        let error = db::migrate(&store.pool).await.unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert!(error.to_string().contains(&net.id), "{error}");
        assert!(error.to_string().contains("dev-101"), "{error}");
        if expected.starts_with("duplicate") { assert!(error.to_string().contains("dev-100"), "{error}"); }
        assert_eq!(store.list_devices(&net.id).await.unwrap(), before);
        let indexes = sqlx::query("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'device_network_%'")
            .fetch_all(&store.pool).await.unwrap();
        assert!(indexes.is_empty());
    }
}

#[tokio::test]
async fn import_is_atomic_rejects_bad_keys_and_deduplicates_canonical_keys() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("import").await.unwrap();
    let a = ImportDevice { wg_public_key: STANDARD.encode([0xab; 32]), address_v4: Some("100.72.16.100".into()), ..Default::default() };
    let bad = ImportDevice { wg_public_key: "bad-key".into(), ..Default::default() };
    assert!(matches!(store.import_devices(&net.id, &[a.clone(), bad]).await, Err(SqlStoreError::InvalidKey)));
    assert!(store.list_devices(&net.id).await.unwrap().is_empty());
    let invalid_address = ImportDevice { address_v4: Some("not-an-ip".into()), ..a.clone() };
    assert!(matches!(store.import_devices(&net.id, &[invalid_address]).await, Err(SqlStoreError::InvalidAddress)));
    let duplicate_address = ImportDevice { wg_public_key: key(2), ..a.clone() };
    assert!(store.import_devices(&net.id, &[a.clone(), duplicate_address]).await.is_err());
    assert!(store.list_devices(&net.id).await.unwrap().is_empty());
    assert_eq!(db::get_network(&store.pool, &net.id).await.unwrap().unwrap().config_epoch, 0);
    let result = store.import_devices(&net.id, &[a.clone(), ImportDevice { wg_public_key: key(0xab), ..a }]).await.unwrap();
    assert_eq!(result.created.len(), 1);
    assert_eq!(result.skipped, vec![key(0xab)]);
    let row = sqlx::query("SELECT wg_public_key FROM device WHERE network_id = $1").bind(&net.id).fetch_one(&store.pool).await.unwrap();
    assert_eq!(row.get::<String, _>("wg_public_key"), key(0xab));
}

#[tokio::test]
async fn pool_exhaustion_and_invalid_key_do_not_consume_invite() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("full").await.unwrap();
    let devices: Vec<_> = (100..=249).map(|host| ImportDevice {
        wg_public_key: key(host), address_v4: Some(format!("100.72.16.{host}")), ..Default::default()
    }).collect();
    store.import_devices(&net.id, &devices).await.unwrap();
    let invite = store.create_invite(&net.id, None, Some(1)).await.unwrap();
    assert!(matches!(store.enroll(&invite.code, "bad", "bad-key", 0).await, Err(SqlStoreError::InvalidKey)));
    assert!(matches!(store.enroll(&invite.code, "full", &key(1), 0).await, Err(SqlStoreError::PoolExhausted)));
    assert_eq!(db::get_invite(&store.pool, &invite.code).await.unwrap().unwrap().uses, 0);
    assert_eq!(store.list_devices(&net.id).await.unwrap().len(), 150);
    assert_eq!(db::get_network(&store.pool, &net.id).await.unwrap().unwrap().config_epoch, 1);
}

#[tokio::test]
async fn revoked_address_migration_recycles_without_losing_tombstone_or_routes() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("recycled").await.unwrap();
    legacy_rows(&store, &net.id, &[key(1), key(2)], &[Some("100.72.16.100"), Some("100.72.16.100")]).await;
    sqlx::query("UPDATE device SET status = 'revoked', auth_token = 'old-token' WHERE id = 'dev-100'").execute(&store.pool).await.unwrap();
    let route = store.advertise_route("dev-100", "10.0.0.0/24").await.unwrap();
    db::migrate(&store.pool).await.unwrap();
    let revoked = db::get_device(&store.pool, "dev-100").await.unwrap().unwrap();
    assert_eq!(revoked.status, DeviceStatus::Revoked);
    assert_eq!(revoked.address_v4, None);
    assert_eq!(store.device_token(&revoked.id).await.unwrap(), None);
    assert_eq!(store.list_device_routes(&revoked.id).await.unwrap(), vec![route]);
    assert_eq!(db::get_device(&store.pool, "dev-101").await.unwrap().unwrap().address_v4.as_deref(), Some("100.72.16.100"));
}

#[tokio::test]
async fn uniqueness_is_network_scoped_and_failed_rotation_keeps_previous_token() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("first").await.unwrap();
    let other = store.create_network("other").await.unwrap();
    let imported = ImportDevice { wg_public_key: key(0xab), address_v4: Some("10.0.0.1".into()), ..Default::default() };
    for network in [&net.id, &other.id] {
        store.import_devices(network, std::slice::from_ref(&imported)).await.unwrap();
    }
    let invite = store.create_invite(&net.id, None, Some(1)).await.unwrap();
    let (device, token) = store.enroll(&invite.code, "rotate", &key(0xab), 0).await.unwrap();
    sqlx::query("CREATE TRIGGER fail BEFORE UPDATE OF auth_token ON device BEGIN SELECT RAISE(ABORT, 'failed rotation'); END")
        .execute(&store.pool).await.unwrap();
    assert!(store.enroll(&invite.code, "rotate", &STANDARD.encode([0xab; 32]), 0).await.is_err());
    assert_eq!(store.device_token(&device.id).await.unwrap(), Some(token));
    assert_eq!(store.list_devices(&net.id).await.unwrap().len(), 1);
    assert_eq!(db::get_invite(&store.pool, &invite.code).await.unwrap().unwrap().uses, 0);
}

#[tokio::test]
async fn migration_tolerates_dirty_tombstones_replaces_old_indexes_and_is_write_idempotent() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("upgrade").await.unwrap();
    legacy_rows(&store, &net.id, &[key(0xab), STANDARD.encode([0xab; 32]), "bad-revoked-key".into()], &[Some("100.72.16.100"), Some("not-an-ip"), None]).await;
    sqlx::query("UPDATE device SET status = 'revoked' WHERE id IN ('dev-101','dev-102')").execute(&store.pool).await.unwrap();
    // Upgrade the Round 1 schema, where the two encodings are distinct strings.
    sqlx::query("CREATE UNIQUE INDEX device_network_key ON device (network_id, wg_public_key)").execute(&store.pool).await.unwrap();
    sqlx::query("CREATE UNIQUE INDEX device_network_v4 ON device (network_id, address_v4)").execute(&store.pool).await.unwrap();
    db::migrate(&store.pool).await.unwrap();
    let devices = store.list_devices(&net.id).await.unwrap();
    assert_eq!(devices[0].wg_public_key, devices[1].wg_public_key);
    assert_eq!(devices[2].wg_public_key, "bad-revoked-key");
    assert_eq!(devices[1].address_v4, None);
    sqlx::query("CREATE TRIGGER no_rewrite BEFORE UPDATE ON device BEGIN SELECT RAISE(ABORT, 'unchanged device rewritten'); END")
        .execute(&store.pool).await.unwrap();
    db::migrate(&store.pool).await.unwrap();
}

#[tokio::test]
async fn revoked_key_with_new_invite_creates_new_device_without_inheriting_routes() {
    let (_dir, _url, store) = fixture().await;
    let net = store.create_network("rejoin").await.unwrap();
    let old_invite = store.create_invite(&net.id, None, Some(1)).await.unwrap();
    let (old, token) = store.enroll(&old_invite.code, "old", &key(1), 0).await.unwrap();
    let route = store.advertise_route(&old.id, "0.0.0.0/0").await.unwrap();
    store.approve_route(&route.id).await.unwrap();
    store.revoke_device(&old.id).await.unwrap();
    assert_eq!(store.device_token(&old.id).await.unwrap(), None);
    assert!(store.device_config(&old.id).await.is_err());
    assert!(matches!(store.enroll(&old_invite.code, "no invitation left", &key(1), 0).await, Err(SqlStoreError::InvalidInvite)));
    let invite = store.create_invite(&net.id, None, Some(2)).await.unwrap();
    // A different device may legitimately take the released address.
    store.enroll(&invite.code, "other", &key(2), 0).await.unwrap();
    let (new, new_token) = store.enroll(&invite.code, "new", &STANDARD.encode([1; 32]), 0).await.unwrap();
    assert_ne!(new.id, old.id);
    assert_ne!(new.address_v4, old.address_v4);
    assert_ne!(new_token, token);
    assert!(!store.device_config(&new.id).await.unwrap().self_exit);
    assert!(store.list_device_routes(&new.id).await.unwrap().is_empty());
    assert_eq!(store.list_device_routes(&old.id).await.unwrap(), vec![Route { approved: true, ..route }]);
    assert_eq!(db::get_device(&store.pool, &old.id).await.unwrap().unwrap().status, DeviceStatus::Revoked);
    assert_eq!(store.list_invites(&net.id).await.unwrap().iter().find(|i| i.code == invite.code).unwrap().uses, 2);
}

#[tokio::test]
async fn next_id_and_revoke_retry_sqlite_busy() {
    // A zero busy_timeout forces the retry path instead of hiding contention in
    // SQLite's built-in waiter. The fixture has just one pooled connection.
    let (_dir, url, store) = fixture().await;
    let net = store.create_network("busy").await.unwrap();
    let invite = store.create_invite(&net.id, None, None).await.unwrap();
    let (device, _) = store.enroll(&invite.code, "device", &key(1), 0).await.unwrap();
    let busy_pool = sqlx::any::AnyPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
    sqlx::query("PRAGMA busy_timeout = 0").execute(&busy_pool).await.unwrap();
    let busy_store = Arc::new(SqlStore { pool: busy_pool, net_index: AtomicU64::new(1), epoch_tx: Mutex::new(HashMap::new()) });
    for revoke in [false, true] {
        let lock = crate::integrity::begin(&store.pool).await.unwrap();
        let task_store = busy_store.clone(); let id = device.id.clone();
        let task = tokio::spawn(async move {
            if revoke { task_store.revoke_device(&id).await } else { task_store.next_seq().await.map(|_| ()) }
        });
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert!(!task.is_finished(), "busy operation must wait and retry");
        lock.commit().await.unwrap();
        task.await.unwrap().unwrap();
    }
    assert_eq!(store.device_token(&device.id).await.unwrap(), None);
}

#[tokio::test]
async fn unknown_status_is_never_active_and_migration_rejects_it_without_changes() {
    for status in ["", "ACTIVE", "disabled", "active "] {
        let (_dir, url, store) = fixture().await;
        let net = store.create_network("unknown-status").await.unwrap();
        let invite = store.create_invite(&net.id, None, None).await.unwrap();
        let (device, token) = store.enroll(&invite.code, "device", &key(1), 0).await.unwrap();
        sqlx::query("UPDATE device SET status = $1 WHERE id = $2")
            .bind(status).bind(&device.id).execute(&store.pool).await.unwrap();
        assert_eq!(db::get_device(&store.pool, &device.id).await.unwrap().unwrap().status, DeviceStatus::Revoked);
        assert_eq!(store.list_devices(&net.id).await.unwrap()[0].status, DeviceStatus::Revoked);
        assert!(matches!(store.device_config(&device.id).await, Err(SqlStoreError::DeviceNotFound)));
        let error = match SqlStore::connect(&url).await {
            Ok(_) => panic!("unknown status must reject startup"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("unknown status"), "{error}");
        assert!(error.contains(&device.id), "{error}");
        assert!(error.contains(&net.id), "{error}");
        let raw = sqlx::query("SELECT status, auth_token, address_v4 FROM device WHERE id = $1")
            .bind(&device.id).fetch_one(&store.pool).await.unwrap();
        assert_eq!(raw.get::<String, _>("status"), status);
        assert_eq!(raw.get::<String, _>("auth_token"), token);
        assert_eq!(raw.get::<Option<String>, _>("address_v4"), device.address_v4);
    }
}
