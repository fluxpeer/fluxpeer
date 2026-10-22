// SPDX-License-Identifier: BSD-3-Clause
//! Confined membership operations for the OpenWrt wrapper. No admin credentials.
use super::*;
use std::io::{Error, ErrorKind};
use std::time::Duration;

/// Manage membership files and the owning daemon, returning credential-free JSON.
/// Joining only enrolls; up is an explicit action. Offline down/leave hold the
/// daemon endpoint so startup cannot race removal of a member's credentials.
pub async fn command(dir: &str, action: &str, iface: Option<&str>, token: Option<&str>, name: Option<String>) -> std::io::Result<serde_json::Value> {
    let dir = Path::new(dir);
    if action == "join" {
        std::fs::create_dir_all(dir)?;
        let slot = reserve_member(dir)?;
        let cfg = tokio::time::timeout(Duration::from_secs(30), crate::join::enroll_config(token.unwrap_or(""), name.filter(|name| !name.trim().is_empty())))
            .await.map_err(Error::other)??;
        let (_, iface) = slot.save(&cfg)?;
        return Ok(serde_json::json!({"ok":true,"iface":iface}));
    }
    if action == "status" { return status(dir).await; }
    if !matches!(action, "up" | "down" | "leave") { return Err(Error::other("unknown membership action")); }
    let iface = iface.ok_or_else(|| Error::other("iface is required"))?;
    member_config(dir, iface)?;
    let connection = if action == "up" {
        // procd acknowledges start before the daemon has bound its IPC listener.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match TcpStream::connect(DAEMON_ADDR).await {
                    Err(error) if error.kind() == ErrorKind::ConnectionRefused => tokio::time::sleep(Duration::from_millis(100)).await,
                    result => break result,
                }
            }
        }).await.map_err(Error::other)?
    } else { TcpStream::connect(DAEMON_ADDR).await };
    match connection {
        Ok(stream) => {
            let token_path = confined_path(dir, "daemon", "token", false)?;
            let token = std::fs::read_to_string(token_path)?;
            let req = serde_json::json!({"cmd":action,"iface":iface,"auth":token.trim()});
            tokio::time::timeout(Duration::from_secs(30), exchange(stream, &req)).await.map_err(Error::other)?
        }
        Err(error) if error.kind() == ErrorKind::ConnectionRefused && action != "up" => {
            let _reservation = TcpListener::bind(DAEMON_ADDR).await?;
            // Never act on an independently running node not owned by this daemon.
            if live_member_ifaces()?.iter().any(|member| member == iface) {
                return Err(Error::other("member is running outside the daemon; stop it first"));
            }
            let daemon = Daemon::new(dir.to_owned(), String::new());
            checked(daemon.dispatch(&serde_json::json!({"cmd":action,"iface":iface})).await)
        }
        Err(error) => Err(error),
    }
}

async fn exchange(stream: TcpStream, req: &serde_json::Value) -> std::io::Result<serde_json::Value> {
    let mut reader = BufReader::new(stream);
    let line = format!("{req}\n");
    reader.get_mut().write_all(line.as_bytes()).await?;
    let mut response = String::new();
    reader.read_line(&mut response).await?;
    checked(serde_json::from_str(&response).map_err(Error::other)?)
}

fn checked(value: serde_json::Value) -> std::io::Result<serde_json::Value> {
    if let Some(error) = value.get("error") { return Err(Error::other(error.to_string())); }
    if value["ok"] != true { return Err(Error::other("invalid daemon acknowledgment")); }
    Ok(value)
}

async fn status(dir: &Path) -> std::io::Result<serde_json::Value> {
    let mut members = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut paths = Vec::new();
    if let Some(entries) = entries {
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if entry.path().extension().is_some_and(|ext| ext == "json") && !name.to_string_lossy().ends_with(".carriers.json") {
                paths.push(confined_file(dir, &name, false)?);
            }
        }
    }
    paths.sort();
    for path in paths {
        let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?).map_err(Error::other)?;
        let iface = cfg["tun_name"].as_str().ok_or_else(|| Error::other("missing member iface"))?;
        member_config(dir, iface)?;
        let endpoint = crate::statusd::socket_path(iface);
        let mut value = serde_json::json!({"interface":{"name":iface,"up":false,
            "device_id":cfg["device_id"],"control":cfg["control_server"]},"peers":[]});
        match tokio::time::timeout(Duration::from_secs(2), crate::show::read_status(&endpoint)).await {
            Ok(Ok(body)) => {
                value = serde_json::from_str(&body).map_err(Error::other)?;
                if value["interface"]["name"].as_str() != Some(iface) { return Err(Error::other("status iface mismatch")); }
                if value["interface"].get("up").is_none() { value["interface"]["up"] = true.into(); }
            },
            Ok(Err(error)) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {},
            result => { value["interface"]["last_error"] = format!("status unavailable: {result:?}").into(); }
        }
        value["interface"]["device_id"] = cfg["device_id"].clone();
        value["interface"]["control"] = cfg["control_server"].clone();
        members.push(value);
    }
    Ok(serde_json::json!({"ok":true,"joined":!members.is_empty(),"status":members}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn two_members_keep_independent_files_and_status_without_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = serde_json::json!({"device_id":"device-a","control_server":"https://control.example","private_key":"secret","auth_token":"secret-token"});
        let (a, iface_a) = reserve_member(dir.path()).unwrap().save(&cfg).unwrap();
        let mut second = cfg.clone(); second["device_id"] = "device-b".into();
        let (b, iface_b) = reserve_member(dir.path()).unwrap().save(&second).unwrap();
        assert_ne!(a, b); assert_ne!(iface_a, iface_b);
        assert_eq!(a.file_name().unwrap(), "fp0.json");
        assert_eq!(b.file_name().unwrap(), "fp1.json");
        let value = status(dir.path()).await.unwrap();
        assert_eq!(value["status"].as_array().unwrap().len(), 2);
        assert!(value["joined"].as_bool().unwrap());
        assert!(!value.to_string().contains("secret"));
        // Legacy node.json remains selectable and is never overwritten by join.
        std::fs::rename(&a, dir.path().join("node.json")).unwrap();
        assert_eq!(member_config(dir.path(), &iface_a).unwrap(), dir.path().canonicalize().unwrap().join("node.json"));
        let (_, third) = reserve_member(dir.path()).unwrap().save(&cfg).unwrap();
        assert_eq!(third, "fp2");
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&std::fs::read(&b).unwrap()).unwrap()["device_id"], "device-b");
        assert!(command(dir.path().to_str().unwrap(), "leave", Some("../fp0"), None, None).await.is_err());
        assert!(a.with_file_name("node.json").exists());
    }

    #[tokio::test]
    async fn authenticated_exchange_propagates_lifecycle_errors() {
        for response in [serde_json::json!({"ok":true,"iface":"fp1"}), serde_json::json!({"error":"cleanup failed"})] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let server = async {
                let mut stream = BufReader::new(listener.accept().await.unwrap().0);
                let mut line = String::new(); stream.read_line(&mut line).await.unwrap();
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(req["iface"], "fp1"); assert_eq!(req["auth"], "member-local-token");
                stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
            };
            let req = serde_json::json!({"cmd":"leave","iface":"fp1","auth":"member-local-token"});
            let (result, ()) = tokio::join!(exchange(client, &req), server);
            assert_eq!(result.is_ok(), response["ok"] == true);
        }
    }
}

#[cfg(all(test, unix))]
mod lifecycle_tests {
    use super::*;
    #[tokio::test]
    async fn down_preserves_membership_leave_removes_only_selected_member() {
        let dir = tempfile::tempdir().unwrap();
        let a = format!("f48a{:x}", std::process::id());
        let b = format!("f48b{:x}", std::process::id());
        for iface in [&a, &b] {
            std::fs::write(dir.path().join(format!("{iface}.json")), serde_json::json!({"tun_name":iface,"device_id":iface}).to_string()).unwrap();
        }
        let mut daemon = Daemon::new(dir.path().into(), "local-token".into());
        daemon.remove_link = Some(|_| Ok(()));
        for iface in [&a, &b] { daemon.processes.spawn(iface, Command::new("/bin/sh").args(["-c", "exec sleep 60"])).unwrap(); }
        let down = daemon.dispatch(&serde_json::json!({"cmd":"down","iface":a})).await;
        assert_eq!(down["ok"], true);
        assert!(dir.path().join(format!("{a}.json")).exists());
        assert!(daemon.processes.contains(&b));
        assert_eq!(daemon.dispatch(&serde_json::json!({"cmd":"leave","iface":a})).await["ok"], true);
        assert!(!dir.path().join(format!("{a}.json")).exists());
        assert!(dir.path().join(format!("{b}.json")).exists());
        assert!(daemon.processes.contains(&b));
        assert!(daemon.dispatch(&serde_json::json!({"cmd":"up","iface":a})).await.get("error").is_some());
        assert_eq!(daemon.dispatch(&serde_json::json!({"cmd":"leave","iface":b})).await["ok"], true);
    }

    #[tokio::test]
    async fn member_join_enrolls_two_networks_without_overwriting_or_starting_nodes() {
        use axum::{routing::post, Json, Router};
        use base64::Engine;
        let dir = tempfile::tempdir().unwrap();
        let router = Router::new()
            .route("/api/v1/enroll/challenge", post(|| async { Json(serde_json::json!({"challenge_id":"test","server_pub":"55".repeat(32)})) }))
            .route("/api/v1/enroll", post(|Json(body): Json<serde_json::Value>| async move {
                Json(serde_json::json!({"id":body["name"],"auth_token":"device-token","address_v4":"10.1.0.2"}))
            }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::json!({"ctrl":format!("http://{}",listener.local_addr().unwrap()),"code":"fixture"}).to_string());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        for (name, iface) in [("network-a","fp0"),("network-b","fp1")] {
            let result = command(dir.path().to_str().unwrap(), "join", None, Some(&token), Some(name.into())).await.unwrap();
            assert_eq!(result["iface"], iface);
            let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join(format!("{iface}.json"))).unwrap()).unwrap();
            assert_eq!(cfg["device_id"], name);
            assert_eq!(cfg["tun_name"], iface);
        }
        let default = command(dir.path().to_str().unwrap(), "join", None, Some(&token), Some(String::new())).await.unwrap();
        assert_eq!(default["iface"], "fp2");
        let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.path().join("fp2.json")).unwrap()).unwrap();
        assert!(!cfg["device_id"].as_str().unwrap().is_empty());
        assert!(command(dir.path().to_str().unwrap(), "join", None, Some("invalid"), None).await.is_err());
        assert!(!dir.path().join("fp3.json").exists());
        assert_eq!(configs(dir.path()).len(), 3);
        server.abort();
    }
}

#[cfg(test)]
mod startup_tests {
    use super::*;
    #[tokio::test]
    async fn occupied_daemon_endpoint_prevents_member_spawn_and_status_errors_are_visible() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cfg = serde_json::json!({"tun_name":"fp0","private_key":"fixture","device_id":"d"});
        reserve_member(dir.path()).unwrap().save(&cfg).unwrap();
        let result = daemon(dir.path().to_str().unwrap().into(), Some(listener.local_addr().unwrap().to_string())).await;
        assert_eq!(result.unwrap_err().kind(), ErrorKind::AddrInUse);
        assert!(!dir.path().join("fp0.log").exists(), "no member spawn before exclusive daemon bind");
        std::fs::write(dir.path().join("fp0.json"), "invalid").unwrap();
        assert!(status(dir.path()).await.is_err(), "corrupt membership must not report not-joined");
    }
}
