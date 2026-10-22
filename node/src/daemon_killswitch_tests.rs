// SPDX-License-Identifier: BSD-3-Clause
#![cfg(unix)]
use super::*;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, Daemon) {
    let dir = tempfile::tempdir().unwrap();
    for iface in ["fp0", "fp1"] {
        std::fs::write(dir.path().join(format!("{iface}.json")), json!({"tun_name":iface,"private_key":"fixture","device_id":"fixture"}).to_string()).unwrap();
    }
    let mut daemon = Daemon::new(dir.path().into(), "test-token".into());
    daemon.guard_root = dir.path().join("firewall");
    (dir, daemon)
}
fn retained(root: &Path, iface: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(root).unwrap();
    let path = root.join(format!("fluxpeer_{}.output.json", hex::encode(iface)));
    std::fs::write(&path, json!({"tun":iface,"backend":"nft","addresses":[]}).to_string()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
fn assert_conflict(value: &serde_json::Value, message: &str) {
    assert_eq!(value["status"], 409, "{value}");
    assert!(value["error"].as_str().unwrap().contains(message), "{value}");
    assert_ne!(value["ok"], true);
}

#[tokio::test]
async fn settings_and_set_config_reject_enabling_before_writes_or_restart() {
    let (dir, daemon) = fixture();
    daemon.processes.spawn("fp1", Command::new("/bin/sleep").arg("60")).unwrap();
    let original = std::fs::read(dir.path().join("fp0.json")).unwrap();
    let settings = daemon.settings(&json!({"iface":"fp0", "kill_switch":true, "use_exit":"auto"})).await;
    assert_conflict(&settings, "membership fp1 is up");
    let mut config: serde_json::Value = serde_json::from_slice(&original).unwrap();
    config["kill_switch"] = json!(true); config["use_exit"] = json!("auto");
    assert_conflict(&daemon.set_config(&json!({"iface":"fp0", "config":config})).await, "membership fp1 is up");
    assert_eq!(std::fs::read(dir.path().join("fp0.json")).unwrap(), original);
    assert!(!daemon.processes.contains("fp0")); assert!(daemon.processes.contains("fp1"));
    assert!(!dir.path().join("fp0.log").exists());
    daemon.processes.stop("fp1").await.unwrap();
    // A dormant setting and a single existing member remain supported on macOS.
    config["use_exit"] = json!("off");
    daemon.store_config(&json!({"iface":"fp0", "config":config})).unwrap();
    daemon.check_member("fp0", &config).unwrap();
}

#[tokio::test]
async fn up_rejects_starting_protected_member_before_journal_and_retained_guard_after_exit() {
    let (dir, daemon) = fixture();
    // No status socket or OUTPUT journal yet: a daemon-owned startup is enough.
    daemon.processes.spawn("fp0", Command::new("/bin/sleep").arg("60")).unwrap();
    daemon.protected_members.lock().insert("fp0".into());
    assert_conflict(&daemon.set_iface("fp1", true).await, "kill-switch active on fp0; disable it first");
    daemon.processes.stop("fp0").await.unwrap();
    retained(&daemon.guard_root, "fp0");
    assert_conflict(&daemon.set_iface("fp1", true).await, "kill-switch active on fp0; disable it first");
    assert!(!daemon.processes.contains("fp1")); assert!(!dir.path().join("fp1.log").exists());
    assert!(!daemon.guard_root.join("fluxpeer_667031.output.json").exists());
    daemon.check_member("fp0", &json!({"kill_switch":true,"use_exit":"auto"})).unwrap();
    std::fs::remove_dir_all(&daemon.guard_root).unwrap();
    daemon.check_member("fp1", &json!({})).unwrap();
}

#[tokio::test]
async fn admission_reservation_rejects_other_up_and_edits_until_start_is_registered() {
    let (dir, daemon) = fixture();
    let original = std::fs::read(dir.path().join("fp1.json")).unwrap();
    let reservation = daemon.admission().unwrap();
    assert_conflict(&daemon.set_iface("fp1", true).await, "admission busy");
    assert_conflict(&daemon.settings(&json!({"iface":"fp1","kill_switch":true})).await, "admission busy");
    assert_conflict(&daemon.set_config(&json!({"iface":"fp1", "config":{"tun_name":"fp1"}})).await, "admission busy");
    assert_eq!(std::fs::read(dir.path().join("fp1.json")).unwrap(), original);
    drop(reservation);
    assert!(daemon.admission().is_ok());
}

#[test]
fn cli_preflights_all_changes_rejects_other_live_members_and_allows_single_member() {
    let (dir, _daemon) = fixture();
    let edit = |obj: &mut serde_json::Map<String, serde_json::Value>| { obj.insert("kill_switch".into(), json!(true)); };
    let original = std::fs::read(dir.path().join("fp0.json")).unwrap();
    for iface in [Some("fp0"), None] {
        let error = edit_configs_with(dir.path(), iface, edit, || Ok(vec!["fp1".into()])).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(error.to_string().contains("membership fp1 is up"));
        assert_eq!(std::fs::read(dir.path().join("fp0.json")).unwrap(), original);
        assert!(!std::fs::read_to_string(dir.path().join("fp1.json")).unwrap().contains("kill_switch"));
    }
    assert_eq!(edit_configs_with(dir.path(), Some("fp0"), edit, || Ok(vec!["fp0".into()])).unwrap(), 1);
    let disable = |obj: &mut serde_json::Map<String, serde_json::Value>| { obj.insert("kill_switch".into(), json!(false)); };
    assert_eq!(edit_configs_with(dir.path(), Some("fp0"), disable, || panic!("disable must not need a live probe")).unwrap(), 1);
}

#[test]
fn live_member_detection_ignores_stale_sockets_and_finds_live_ones() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("fp0.sock"); let stale = dir.path().join("fp1.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    assert_eq!(live_member_paths(vec![live, stale, dir.path().join("missing.sock")]).unwrap(), ["fp0"]);
}

#[test]
fn file_node_preflight_rejects_foreign_retained_guard_without_touching_it() {
    let root = tempfile::tempdir().unwrap();
    crate::firewall::client::ensure_exclusive_at(root.path(), "fp1").unwrap();
    retained(root.path(), "fp0");
    let path = root.path().join("fluxpeer_667030.output.json"); let before = std::fs::read(&path).unwrap();
    let error = crate::firewall::client::ensure_exclusive_at(root.path(), "fp1").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    assert_eq!(error.to_string(), "kill-switch active on fp0; disable it first");
    assert_eq!(std::fs::read(path).unwrap(), before);
    crate::firewall::client::ensure_exclusive_at(root.path(), "fp0").unwrap();
}

#[tokio::test]
async fn single_member_up_is_idempotent_with_its_own_retained_guard() {
    let (_dir, daemon) = fixture();
    retained(&daemon.guard_root, "fp0");
    daemon.processes.spawn("fp0", Command::new("/bin/sleep").arg("60")).unwrap();
    let reply = daemon.set_iface("fp0", true).await;
    assert_eq!(reply, json!({"ok":true,"iface":"fp0","up":true}));
    assert_eq!(daemon.processes.ifaces(), ["fp0"]);
    daemon.processes.stop("fp0").await.unwrap();
}
