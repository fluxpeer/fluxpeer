// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, Daemon) {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("config");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("fp0.json"), json!({"tun_name":"fp0", "private_key":"secret", "device_id":"d0"}).to_string()).unwrap();
    std::fs::write(dir.join("fp0.log"), "registered log\n").unwrap();
    let daemon = Daemon::new(dir, "local-token".into());
    (root, daemon)
}

async fn rejects_every_api(daemon: &Daemon, iface: &str) {
    for cmd in ["up", "down", "settings", "config", "get_config", "set-config", "set_config", "leave", "logs"] {
        let request = json!({"cmd":cmd, "iface":iface, "mtu":1280, "config":{"private_key":"new", "tun_name":iface}});
        let response = daemon.dispatch(&request).await;
        assert_eq!(response["status"], 400, "{cmd}: {iface}: {response}");
        assert!(response.get("error").is_some());
        // Exercise admin handler validation independently of the feature gate.
        if cmd == "set-config" { assert_eq!(daemon.set_config(&request).await["status"], 400); }
    }
    assert!(daemon.processes.ifaces().is_empty());
}

#[tokio::test]
async fn every_iface_api_rejects_traversal_absolute_invalid_and_unregistered_names() {
    let (root, daemon) = fixture();
    let outside = root.path().join("outside");
    std::fs::write(outside.with_extension("json"), "outside config").unwrap();
    std::fs::write(outside.with_extension("log"), "outside log").unwrap();
    let original = std::fs::read(daemon.dir.join("fp0.json")).unwrap();
    for iface in ["../outside", outside.to_str().unwrap(), "missing", "", "fp/0", "fp\\0", "fp.0", "é", "abcdefghijklmnop", "--help"] {
        rejects_every_api(&daemon, iface).await;
    }
    assert_eq!(std::fs::read(outside.with_extension("json")).unwrap(), b"outside config");
    assert_eq!(std::fs::read(outside.with_extension("log")).unwrap(), b"outside log");
    assert_eq!(std::fs::read(daemon.dir.join("fp0.json")).unwrap(), original);
}

#[cfg(unix)]
#[tokio::test]
async fn every_iface_api_rejects_config_and_log_symlinks_including_dangling_targets() {
    use std::os::unix::fs::symlink;
    let (root, daemon) = fixture();
    let outside = root.path().join("outside");
    std::fs::write(&outside, json!({"tun_name":"fp0","private_key":"outside"}).to_string()).unwrap();
    let original = std::fs::read(&outside).unwrap();
    for ext in ["json", "log"] {
        let path = daemon.dir.join(format!("fp0.{ext}"));
        let saved = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        for target in [&outside, &root.path().join("nonexistent"), &daemon.dir.join("inside")] {
            symlink(target, &path).unwrap();
            rejects_every_api(&daemon, "fp0").await;
            assert!(configs(&daemon.dir).is_empty());
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::write(path, saved).unwrap();
    }
    assert_eq!(std::fs::read(&outside).unwrap(), original);
    assert!(!root.path().join("nonexistent").exists());
}

#[tokio::test]
async fn membership_and_replacement_tun_must_match_and_safe_reads_still_work() {
    let (_root, daemon) = fixture();
    assert_eq!(daemon.get_config("fp0")["config"]["private_key"], "<redacted>");
    assert_eq!(daemon.logs("fp0", 10)["log"], "registered log");
    for iface in ["fp0", "FP_1-a", "abcdefghijklmno"] { assert!(valid_iface(iface)); }
    let original = std::fs::read(daemon.dir.join("fp0.json")).unwrap();
    for replacement in ["../outside", "fp1", ""] {
        let response = daemon.set_config(&json!({"iface":"fp0", "config":{"tun_name":replacement,"private_key":"new"}})).await;
        assert_eq!(response["status"], 400);
        assert_eq!(std::fs::read(daemon.dir.join("fp0.json")).unwrap(), original);
    }
    std::fs::write(daemon.dir.join("fp0.json"), json!({"tun_name":"../outside"}).to_string()).unwrap();
    rejects_every_api(&daemon, "fp0").await;
    assert!(configs(&daemon.dir).is_empty());
}

#[tokio::test]
async fn authenticated_tcp_response_preserves_error_and_exposes_bad_request_status() {
    let (_root, daemon) = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    let server = tokio::spawn(async move { daemon.handle(stream).await.unwrap(); });
    client.write_all(b"{\"auth\":\"local-token\",\"cmd\":\"leave\",\"iface\":\"../outside\"}\n").await.unwrap();
    let mut line = String::new();
    BufReader::new(client).read_line(&mut line).await.unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["status"], 400);
    assert!(response["error"].is_string());
    server.await.unwrap();
}

#[test]
fn custom_config_filenames_remain_registered_and_duplicate_ifaces_are_rejected() {
    let (_root, daemon) = fixture();
    let custom = daemon.dir.join("custom-membership.json");
    std::fs::rename(daemon.dir.join("fp0.json"), &custom).unwrap();
    assert_eq!(daemon.get_config("fp0")["config"]["device_id"], "d0");
    assert_eq!(member_config(&daemon.dir, "fp0").unwrap(), custom.canonicalize().unwrap());
    std::fs::copy(&custom, daemon.dir.join("duplicate.json")).unwrap();
    assert_eq!(daemon.get_config("fp0")["status"], 400);
}

#[cfg(unix)]
#[tokio::test]
async fn daemon_join_skips_dangling_slot_and_reports_start_or_save_failure_without_fallback() {
    use base64::Engine;
    use fluxpeer_control_server::{sql_router, sql_store::SqlStore};
    let store = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
    let network = store.create_network("join-safety").await.unwrap();
    let invite = store.create_invite(&network.id, None, Some(4)).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = sql_router(store.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json!({"ctrl":origin,"code":invite.code}).to_string());
    let (root, daemon) = fixture();
    std::fs::remove_file(daemon.dir.join("fp0.json")).unwrap();
    let outside = root.path().join("outside-secret");
    std::os::unix::fs::symlink(&outside, daemon.dir.join("fp0.json")).unwrap();
    let outside_log = root.path().join("outside-log");
    std::os::unix::fs::symlink(&outside_log, daemon.dir.join("fp1.log")).unwrap();
    let response = daemon.join_with(&token, |path| {
        assert_eq!(path.file_name().unwrap(), "fp2.json");
        Err(std::io::Error::other("injected spawn failure"))
    }).await;
    assert!(response.get("ok").is_none());
    assert!(response["error"].as_str().unwrap().contains("start failed"));
    assert!(!outside.exists()); assert!(!outside_log.exists());
    assert_eq!(store.list_invites(&network.id).await.unwrap()[0].uses, 1);
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(daemon.dir.join("fp2.json")).unwrap()).unwrap();
    assert_eq!(saved["private_key"].as_str().unwrap().len(), 64);
    assert!(!saved["auth_token"].as_str().unwrap().is_empty());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(daemon.dir.join("fp2.json")).unwrap().permissions().mode() & 0o777, 0o600);
    // The daemon must never invoke the CLI fallback on a save failure.
    let cwd_fallback = std::env::current_dir().unwrap().join("fluxpeer-node.json");
    let before = std::fs::read(&cwd_fallback).ok();
    let failed = Daemon::new(root.path().join("missing-dir"), String::new());
    let response = failed.join_with(&token, |_| panic!("failed save cannot spawn")).await;
    assert!(response.get("ok").is_none());
    assert!(response["error"].as_str().unwrap().contains("save failed"));
    assert_eq!(std::fs::read(&cwd_fallback).ok(), before);
    assert!(!root.path().join("fluxpeer-node.json").exists());
    assert_eq!(store.list_invites(&network.id).await.unwrap()[0].uses, 1);
    // An actual failed create verifies directory writability before HTTP enroll.
    let blocked = root.path().join("read-only"); std::fs::create_dir(&blocked).unwrap();
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o500)).unwrap();
    // Root bypasses directory permissions; this branch runs for the native user.
    // SAFETY: geteuid has no arguments or memory preconditions.
    if unsafe { libc::geteuid() } != 0 {
        let failed = Daemon::new(blocked.clone(), String::new());
        let response = failed.join_with(&token, |_| panic!("failed preflight cannot spawn")).await;
        assert!(response["error"].as_str().unwrap().contains("preflight"));
        assert_eq!(store.list_invites(&network.id).await.unwrap()[0].uses, 1);
    }
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
    let response = daemon.join_with("invalid-token", |_| panic!("failed enroll cannot spawn")).await;
    assert!(response.get("ok").is_none());
    assert!(!daemon.dir.join("fp3.json").exists(), "failed enroll must release its empty reservation");
    server.abort();
}

#[test]
fn import_is_exclusive_and_preserves_existing_and_custom_memberships() {
    let (_root, daemon) = fixture();
    std::fs::rename(daemon.dir.join("fp0.json"), daemon.dir.join("custom.json")).unwrap();
    std::fs::write(daemon.dir.join("fp1.json"), "existing unrelated file").unwrap();
    let request = json!({"config":{"private_key":"new-key","device_id":"new"}});
    let response = daemon.import_with(&request, |_| Ok(()));
    assert_eq!(response["iface"], "fp2"); assert_eq!(response["ok"], true);
    assert_eq!(std::fs::read(daemon.dir.join("fp1.json")).unwrap(), b"existing unrelated file");
    assert!(!daemon.dir.join("fp0.json").exists());
    let response = daemon.import_with(&request, |_| Ok(()));
    assert_eq!(response["iface"], "fp3");
    // Exclusive open also handles a file created after the slot precheck.
    let path = confined_path(&daemon.dir, "fp4", "json", true).unwrap();
    std::fs::write(&path, "racing winner").unwrap();
    assert_eq!(write_json(&path, &request["config"], true).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"racing winner");
}

#[cfg(unix)]
#[test]
fn nofollow_blocks_leaf_replacement_between_check_and_config_or_log_write() {
    let (root, daemon) = fixture();
    let outside = root.path().join("external"); std::fs::write(&outside, "unchanged").unwrap();
    for extension in ["json", "log"] {
        let path = confined_path(&daemon.dir, "fp0", extension, false).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(open_output(&path, false).is_err());
        assert!(write_json(&path, &json!({"private_key":"secret"}), false).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn running_iface_can_stop_or_leave_with_missing_or_duplicate_membership() {
    for command in ["down", "leave"] {
        for duplicate in [false, true] {
            let (_root, daemon) = fixture();
            let iface = format!("fpt30{:x}", std::process::id());
            std::fs::write(daemon.dir.join("fp0.json"), json!({"tun_name":iface,"private_key":"fixture"}).to_string()).unwrap();
            // A harmless child fixture, never a real node or tunnel.
            daemon.processes.spawn(&iface, Command::new("/bin/sleep").arg("60")).unwrap();
            if duplicate {
                std::fs::copy(daemon.dir.join("fp0.json"), daemon.dir.join("copy.json")).unwrap();
                let statuses = daemon.annotate_status(json!([]));
                assert_eq!(statuses[0]["membership_error"], "multiple membership configs");
                assert_eq!(daemon.networks()[0]["membership_error"], "multiple membership configs");
            } else { std::fs::remove_file(daemon.dir.join("fp0.json")).unwrap(); }
            let response = daemon.dispatch(&json!({"cmd":command,"iface":iface})).await;
            assert!(daemon.processes.ifaces().is_empty());
            if command == "leave" {
                assert_eq!(response["left"], false); assert_eq!(response["up"], false);
                assert!(response["error"].is_string()); assert!(response.get("ok").is_none());
            } else { assert_eq!(response["ok"], true, "{response}"); }
        }
    }
}

#[test]
fn leading_hyphen_is_invalid_even_for_a_membership_file() {
    let (_root, daemon) = fixture();
    std::fs::write(daemon.dir.join("custom.json"), json!({"tun_name":"-bad","private_key":"secret"}).to_string()).unwrap();
    assert!(!valid_iface("-bad"));
    assert!(daemon.validate_operation("-bad", true).is_err());
    assert_eq!(daemon.get_config("-bad")["status"], 400);
}

#[test]
fn set_config_preserves_disk_private_key_when_redacted_or_omitted() {
    let (_root, daemon) = fixture();
    let path = daemon.dir.join("fp0.json");
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for omitted in [false, true] {
        let mut cfg = daemon.get_config("fp0")["config"].clone();
        if omitted { cfg.as_object_mut().unwrap().remove("private_key"); }
        cfg["mtu"] = json!(1280);
        assert_eq!(daemon.store_config(&json!({"iface":"fp0", "config":cfg})).unwrap(), path.canonicalize().unwrap());
        let stored: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored["private_key"], original["private_key"]);
        assert_eq!(stored["mtu"], 1280);
    }
    daemon.store_config(&json!({"iface":"fp0", "config":{"tun_name":"fp0", "private_key":"explicit-new-key"}})).unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(stored["private_key"], "explicit-new-key");
    assert!(daemon.processes.ifaces().is_empty());
}

#[test]
fn set_config_rejects_invalid_keys_or_missing_original_without_writing() {
    let (_root, daemon) = fixture();
    let path = daemon.dir.join("fp0.json");
    let saved = std::fs::read(&path).unwrap();
    for invalid in [json!(null), json!(42), json!(""), json!(false)] {
        assert!(daemon.store_config(&json!({"iface":"fp0", "config":{"tun_name":"fp0", "private_key":invalid}})).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), saved);
    }
    for original in [json!({"tun_name":"fp0"}), json!({"tun_name":"fp0", "private_key":"<redacted>"})] {
        std::fs::write(&path, original.to_string()).unwrap();
        for cfg in [json!({"tun_name":"fp0"}), json!({"tun_name":"fp0", "private_key":"<redacted>"})] {
            assert!(daemon.store_config(&json!({"iface":"fp0", "config":cfg})).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original.to_string());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_link_cleanup_runs_off_async_worker_and_preserves_errors() {
    let async_thread = std::thread::current().id();
    cleanup_link_with("fp-test".into(), move |iface| {
        assert_eq!(iface, "fp-test");
        assert_ne!(std::thread::current().id(), async_thread);
        Ok(())
    }).await.unwrap();
    let denied = crate::apply::test_support::error(Some(1), "Operation not permitted");
    let expected = denied.clone();
    assert_eq!(cleanup_link_with("fp-test".into(), |_| Err(denied)).await, Err(expected));
    cleanup_link_with("fp-test".into(), |_| Err(crate::apply::test_support::error(Some(1), "Cannot find device \"fp-test\""))).await.unwrap();
}
