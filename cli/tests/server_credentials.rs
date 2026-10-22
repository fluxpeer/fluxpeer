// SPDX-License-Identifier: BSD-3-Clause
//! Exercise actual CLI argument/env resolution without mutating the test process environment.
use axum::{Json, Router, routing::get};
use fluxpeer_cli::Client;
use std::process::Command;

fn fp(directory: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fp"));
    command.env_remove("FLUXPEER_SERVER").env_remove("FLUXPEER_CONTROL_URL")
        .env("FLUXPEER_ADMIN_PASSWORD", "test-admin-secret")
        .args(["--config-dir", directory.to_str().unwrap()]);
    command
}

#[test]
fn missing_or_ambiguous_server_errors_and_import_dry_run_stays_offline() {
    let dir = tempfile::tempdir().unwrap();
    let missing = fp(dir.path()).args(["network", "list"]).output().unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no control server"));
    for (name, url) in [("a", "http://control-a.invalid"), ("b", "http://control-b.invalid")] {
        std::fs::write(dir.path().join(format!("{name}.json")), serde_json::json!({"device_id": name, "control_server": url}).to_string()).unwrap();
    }
    let ambiguous = fp(dir.path()).args(["network", "list"]).output().unwrap();
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("multiple joined control servers"));
    let conf = dir.path().join("wg.conf");
    std::fs::write(&conf, "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n").unwrap();
    let dry = fp(dir.path()).args(["import", conf.to_str().unwrap(), "--dry-run"]).output().unwrap();
    assert!(dry.status.success(), "{}", String::from_utf8_lossy(&dry.stderr));
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_server_precedes_env_and_joined_config_credentials_are_anonymous() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let app = Router::new().route("/api/v1/networks", get(move |headers: axum::http::HeaderMap| {
        let tx = tx.clone();
        async move { tx.send(headers).await.unwrap(); Json(serde_json::json!([])) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    std::fs::write(dir.path().join("fp0.json"), serde_json::json!({"device_id": "d1", "control_server": origin}).to_string()).unwrap();
    for explicit in [false, true] {
        let mut command = fp(dir.path());
        if explicit { command.env("FLUXPEER_SERVER", "http://ignored.invalid").args(["--server", &origin]); }
        let output = tokio::task::spawn_blocking(move || command.args(["network", "list"]).output().unwrap()).await.unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let headers = rx.recv().await.unwrap();
        assert_eq!(headers.get("authorization").and_then(|value| value.to_str().ok()), explicit.then_some("Bearer test-admin-secret"));
    }
    let mut command = fp(dir.path());
    command.env("FLUXPEER_SERVER", &origin);
    let output = tokio::task::spawn_blocking(move || command.args(["network", "list"]).output().unwrap()).await.unwrap();
    assert!(output.status.success());
    assert_eq!(rx.recv().await.unwrap()["authorization"], "Bearer test-admin-secret");
    Client::new(&origin).list_networks().await.unwrap();
    assert!(!rx.recv().await.unwrap().contains_key("authorization"));
    server.abort();
}

#[tokio::test]
async fn sdk_rejects_credential_redirects_userinfo_and_invalid_bearers() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    let target = Router::new().route("/api/v1/networks", get(move || {
        let tx = tx.clone();
        async move { tx.send(()).await.unwrap(); Json(serde_json::json!([])) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_origin = format!("http://{}", listener.local_addr().unwrap());
    let target_server = tokio::spawn(async move { axum::serve(listener, target).await.unwrap() });
    let destination = format!("{target_origin}/api/v1/networks");
    let delete_destination = destination.clone();
    let redirect = Router::new().route("/api/v1/networks", get(move || {
        let destination = destination.clone();
        async move { axum::response::Redirect::temporary(&destination) }
    })).route("/api/v1/devices/d1", axum::routing::delete(move || {
        let destination = delete_destination.clone();
        async move { axum::response::Redirect::temporary(&destination) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let redirect_server = tokio::spawn(async move { axum::serve(listener, redirect).await.unwrap() });
    assert!(Client::with_password(&origin, "admin-secret").list_networks().await.is_err());
    assert!(Client::with_password(&origin, "admin-secret").revoke_device("d1").await.is_err());
    assert!(Client::with_password(&target_origin, "invalid\nheader").list_networks().await.is_err());
    let with_userinfo = target_origin.replacen("http://", "http://user:password@", 1);
    assert!(Client::new(with_userinfo).list_networks().await.is_err());
    assert!(rx.try_recv().is_err(), "request reached an unauthorized target");
    redirect_server.abort();
    target_server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_and_alias_servers_are_explicit_and_conflicts_send_no_request() {
    let dir = tempfile::tempdir().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let app = Router::new().route("/api/v1/networks", get(move |headers: axum::http::HeaderMap| {
        let tx = tx.clone();
        async move { tx.send(headers).await.unwrap(); Json(serde_json::json!([])) }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    std::fs::write(dir.path().join("fp0.json"), serde_json::json!({"device_id": "d1", "control_server": origin}).to_string()).unwrap();
    // Each name, and equal values under both names, must preserve explicit auth.
    for names in [vec!["FLUXPEER_CONTROL_URL"], vec!["FLUXPEER_SERVER"], vec!["FLUXPEER_CONTROL_URL", "FLUXPEER_SERVER"]] {
        let mut command = fp(dir.path());
        for name in names { command.env(name, &origin); }
        let output = tokio::task::spawn_blocking(move || command.args(["network", "list"]).output().unwrap()).await.unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let headers = rx.recv().await.unwrap();
        assert_eq!(headers.get("authorization").and_then(|value| value.to_str().ok()), Some("Bearer test-admin-secret"));
    }
    // The flag takes precedence over either unambiguous environment source.
    for name in ["FLUXPEER_CONTROL_URL", "FLUXPEER_SERVER"] {
        let mut command = fp(dir.path());
        command.env(name, "http://ignored.invalid").args(["--server", &origin]);
        let output = tokio::task::spawn_blocking(move || command.args(["network", "list"]).output().unwrap()).await.unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(rx.recv().await.unwrap()["authorization"], "Bearer test-admin-secret");
    }
    // Conflicting environment is rejected before any HTTP request, even with a flag.
    for flag in [false, true] {
        let mut command = fp(dir.path());
        command.env("FLUXPEER_CONTROL_URL", &origin).env("FLUXPEER_SERVER", "http://conflict.invalid");
        if flag { command.args(["--server", &origin]); }
        let output = tokio::task::spawn_blocking(move || command.args(["network", "list"]).output().unwrap()).await.unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("FLUXPEER_CONTROL_URL and FLUXPEER_SERVER disagree"));
        assert!(rx.try_recv().is_err(), "conflicting environment sent a request");
    }
    server.abort();
}
