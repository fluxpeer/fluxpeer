// SPDX-License-Identifier: BSD-3-Clause
#![cfg(unix)]
use super::*;
use serde_json::json;
use tokio::time::{Duration, timeout};

fn fixture() -> (tempfile::TempDir, Daemon, String) {
    let dir = tempfile::tempdir().unwrap();
    let iface = format!("fpt40{:x}", std::process::id());
    std::fs::write(dir.path().join("member.json"), json!({"tun_name":iface,"private_key":"fixture","device_id":"fixture"}).to_string()).unwrap();
    let daemon = Daemon::new(dir.path().into(), "test-token".into());
    (dir, daemon, iface)
}
async fn until(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !ready() { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await.unwrap();
}
async fn request(daemon: &Daemon, value: serde_json::Value) -> serde_json::Value {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = async {
        let mut stream = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        stream.write_all(format!("{value}\n").as_bytes()).await.unwrap();
        let mut reply = String::new(); stream.read_to_string(&mut reply).await.unwrap();
        serde_json::from_str(&reply).unwrap()
    };
    let server = async { daemon.handle(listener.accept().await.unwrap().0).await.unwrap(); };
    let (reply, ()) = tokio::join!(client, server); reply
}
#[tokio::test]
async fn natural_exit_is_reaped_without_status_polling_and_allows_restart() {
    let (_dir, daemon, iface) = fixture();
    daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c", "exit 7"])).unwrap();
    // No networks()/try_wait() poll is needed to clear the active entry.
    until(|| !daemon.processes.contains(&iface)).await;
    assert_eq!(daemon.networks()[0]["up"], false);
    assert_eq!(daemon.networks()[0]["last_exit_code"], 7);
    assert!(daemon.networks()[0]["last_error"].as_str().unwrap().contains('7'));
    daemon.processes.spawn(&iface, Command::new("/bin/sleep").arg("60")).unwrap();
    assert_eq!(daemon.networks()[0]["up"], true);
    assert!(daemon.networks()[0]["last_exit_code"].is_null());
    daemon.processes.stop(&iface).await.unwrap();
    assert!(!daemon.processes.contains(&iface));
}
#[tokio::test]
async fn occupied_operation_rejects_up_down_edits_and_shutdown_without_mutation() {
    let (dir, daemon, iface) = fixture();
    let bytes = std::fs::read(dir.path().join("member.json")).unwrap();
    let pending_up = daemon.processes.operation(&iface).unwrap();
    let (a, b) = tokio::join!(daemon.set_iface(&iface, true), daemon.set_iface(&iface, false));
    assert_eq!(a["status"], 409); assert_eq!(b["status"], 409);
    assert_eq!(daemon.settings(&json!({"iface":iface,"mtu":1400})).await["status"], 409);
    assert_eq!(daemon.leave(&iface).await["status"], 409);
    assert_eq!(daemon.shutdown().await["status"], 409);
    assert_eq!(std::fs::read(dir.path().join("member.json")).unwrap(), bytes);
    assert!(daemon.processes.ifaces().is_empty());
    // Another interface remains independently operable.
    let other = daemon.processes.operation("fp-other").unwrap(); drop(other);
    drop(pending_up);
    assert!(daemon.processes.operation(&iface).is_ok());
}
#[tokio::test]
async fn duplicate_start_spawns_one_child_and_stop_serializes_restart() {
    let (dir, daemon, iface) = fixture();
    let counter = dir.path().join("starts");
    for _ in 0..2 {
        let _operation = daemon.processes.operation(&iface).unwrap();
        daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c", "printf x >> \"$1\"; exec sleep 60", "fixture"]).arg(&counter)).unwrap();
    }
    until(|| counter.exists()).await;
    assert_eq!(std::fs::read(&counter).unwrap(), b"x");
    let stopping = daemon.processes.operation(&iface).unwrap();
    assert_eq!(daemon.set_iface(&iface, true).await["status"], 409);
    daemon.processes.stop(&iface).await.unwrap();
    drop(stopping);
    let _operation = daemon.processes.operation(&iface).unwrap();
    daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c", "exit 0"])).unwrap();
    until(|| !daemon.processes.contains(&iface)).await;
    assert_eq!(daemon.processes.snapshot(&iface).1.unwrap().code, Some(0));
}
#[tokio::test]
async fn token_authorized_shutdown_waits_for_cleanup_and_prevents_new_up() {
    let (dir, daemon, iface) = fixture();
    let ready = dir.path().join("ready"); let cleaned = dir.path().join("cleaned");
    daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c",
        "trap 'printf done > \"$2\"; exit 0' TERM; printf ready > \"$1\"; while :; do sleep 0.05; done", "fixture"]).arg(&ready).arg(&cleaned)).unwrap();
    until(|| ready.exists()).await;
    for auth in [json!(null), json!("wrong")] {
        let reply = request(&daemon, json!({"cmd":"shutdown","auth":auth})).await;
        assert_eq!(reply["error"], "unauthorized"); assert!(daemon.processes.contains(&iface));
    }
    let reply = request(&daemon, json!({"cmd":"shutdown","auth":"test-token"})).await;
    assert_eq!(reply, json!({"ok":true,"shutdown":true}));
    assert_eq!(std::fs::read(cleaned).unwrap(), b"done");
    assert!(daemon.processes.ifaces().is_empty());
    timeout(Duration::from_millis(100), daemon.exit.notified()).await.unwrap();
    assert_eq!(daemon.set_iface(&iface, true).await["status"], 409);
}
#[tokio::test]
async fn token_authorized_down_is_available_without_admin_privileges() {
    let (_dir, daemon, iface) = fixture();
    daemon.processes.spawn(&iface, Command::new("/bin/sleep").arg("60")).unwrap();
    let denied = request(&daemon, json!({"cmd":"down","iface":iface,"auth":"wrong"})).await;
    assert_eq!(denied["error"], "unauthorized"); assert!(daemon.processes.contains(&iface));
    let reply = request(&daemon, json!({"cmd":"down","iface":iface,"auth":"test-token"})).await;
    assert_eq!(reply["ok"], true); assert_eq!(reply["up"], false);
}
#[tokio::test]
async fn failed_cleanup_stays_pending_and_shutdown_does_not_ack_success() {
    let (dir, daemon, iface) = fixture();
    let ready = dir.path().join("ready");
    daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c",
        "trap 'exit 9' TERM; printf ready > \"$1\"; while :; do sleep 0.05; done", "fixture"]).arg(&ready)).unwrap();
    until(|| ready.exists()).await;
    let reply = daemon.shutdown().await;
    assert!(reply["error"].as_str().unwrap().contains('9'));
    assert!(reply.get("ok").is_none());
    assert!(daemon.processes.cleanup_ifaces().contains(&iface));
    assert!(daemon.processes.operation(&iface).is_ok());
    assert_eq!(daemon.networks()[0]["last_exit_code"], 9);
    assert!(daemon.shutdown().await["error"].as_str().unwrap().contains('9'));
}

#[tokio::test]
async fn unresponsive_member_reports_forced_termination_instead_of_success() {
    let (dir, daemon, iface) = fixture();
    let ready = dir.path().join("ready");
    daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c",
        "trap '' TERM; printf ready > \"$1\"; exec sleep 60", "fixture"]).arg(&ready)).unwrap();
    until(|| ready.exists()).await;
    let stopped = daemon.processes.stop(&iface).await;
    assert!(stopped.unwrap_err().to_string().contains("forced termination"));
    assert!(!daemon.processes.contains(&iface));
    assert_eq!(daemon.networks()[0]["forced_termination"], true);
    assert!(daemon.processes.stop(&iface).await.is_err());
}

#[tokio::test]
async fn failed_spawn_releases_reservation_and_retains_error_for_retry() {
    let (dir, daemon, iface) = fixture();
    {
        let _operation = daemon.processes.operation(&iface).unwrap();
        assert!(daemon.processes.spawn(&iface, &mut Command::new(dir.path().join("missing-binary"))).is_err());
    }
    assert!(!daemon.processes.contains(&iface));
    assert!(daemon.networks()[0]["last_error"].is_string());
    let _operation = daemon.processes.operation(&iface).unwrap();
    daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c", "exit 0"])).unwrap();
    until(|| !daemon.processes.contains(&iface)).await;
    assert!(daemon.networks()[0]["last_error"].is_null());
    drop(_operation);
    // A reaped member can still be safely stopped if its config was removed.
    std::fs::remove_file(dir.path().join("member.json")).unwrap();
    assert!(daemon.validate_operation(&iface, true).is_ok());
    assert_eq!(daemon.set_iface(&iface, false).await["ok"], true);
    assert!(!daemon.processes.needs_cleanup(&iface));
}

#[tokio::test]
async fn vanished_tun_allows_stop_and_token_authorized_shutdown() {
    let (_dir, mut daemon, iface) = fixture();
    daemon.remove_link = Some(|iface| Err(crate::apply::test_support::error(
        Some(1), &format!("Cannot find device \"{iface}\""),
    )));
    daemon.processes.spawn(&iface, Command::new("/bin/sh").args(["-c", "exit 0"])).unwrap();
    until(|| !daemon.processes.contains(&iface)).await;
    daemon.stop_iface(&iface).await.unwrap();
    assert_eq!(request(&daemon, json!({"cmd":"shutdown","auth":"test-token"})).await,
        json!({"ok":true,"shutdown":true}));
    timeout(Duration::from_millis(100), daemon.exit.notified()).await.unwrap();
}
