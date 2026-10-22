//! One-command onboarding: `fluxpeer join <token>`.
//!
//! A join token is `fp://join/<base64url(JSON)>` where the JSON is
//! `{"ctrl":"<control-server URL>","code":"<invite code>"}` — exactly what
//! admin-lite renders as a copyable string + QR. `join` decodes it, generates a
//! keypair, enrolls against the control-server (the open `/enroll` endpoint),
//! writes a node config, and (unless `--no-run`) brings the tunnel up — so sharing
//! one string/QR is all it takes for someone to join the mesh.

use std::io::{Error, Write};
use std::path::PathBuf;

use base64::Engine;
use fluxpeer_sdk::Client;

use crate::config::keypair;

/// The token's payload (also the shape admin-lite encodes).
struct JoinToken {
    ctrl: String,
    code: String,
}

/// Decode `fp://join/<b64url>` (or a bare base64url blob) into its `(ctrl, code)`.
fn decode_token(token: &str) -> std::io::Result<JoinToken> {
    let blob = token.trim().strip_prefix("fp://join/").unwrap_or_else(|| token.trim());
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(blob.trim_end_matches('='))
        .map_err(|e| Error::other(format!("invalid join token (base64): {e}")))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| Error::other(format!("invalid join token (json): {e}")))?;
    let ctrl = v["ctrl"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::other("join token missing \"ctrl\""))?
        .trim_end_matches('/')
        .to_string();
    let code = v["code"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::other("join token missing \"code\""))?
        .to_string();
    Ok(JoinToken { ctrl, code })
}

pub(crate) async fn enroll_device(token: &str, name: &str, private: &str) -> std::io::Result<serde_json::Value> {
    let JoinToken { ctrl, code } = decode_token(token)?;
    let mut device = Client::new(ctrl.clone()).enroll(&code, name, private).await.map_err(Error::other)?;
    let object = device.as_object_mut().ok_or_else(|| Error::other("invalid enrollment response"))?;
    object.insert("control_server".into(), ctrl.into());
    Ok(device)
}

/// This host's name, for a friendly device label (admin can rename later).
fn default_name() -> String {
    #[cfg(unix)]
    let host = std::fs::read_to_string("/etc/hostname").ok();
    #[cfg(windows)]
    let host = std::env::var("COMPUTERNAME").ok();
    host.map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "fp-node".to_string())
}

/// Run the join flow. `name` overrides the device label; `out` overrides the config
/// path; `no_run` writes the config but doesn't bring the tunnel up.
/// Decode a join token → keygen → enroll → write a node config (auto-assigning a
/// free tun/port slot unless `out` pins a path). Returns `(config_path, tun_name)`.
/// CLI-only persistence; the daemon uses enroll_config and exclusive confined
/// member creation instead of this legacy output-path/fallback policy.
pub(crate) async fn enroll_and_write(
    token: &str,
    name: Option<String>,
    out: Option<String>,
    dir: &std::path::Path,
) -> std::io::Result<(PathBuf, String)> {
    let Enrollment { mut config, name, address } = enroll(token, name).await?;
    let cfg = &mut config;
    // Multi-network: each membership is its own config in the config dir with a
    // distinct tun/port (auto-assigned), so one device can be in many networks.
    let (path, tun_name, listen_port) = match out {
        Some(o) => (PathBuf::from(o), "fp0".to_string(), 41820u16),
        None => assign_slot(dir),
    };
    cfg["listen_port"] = listen_port.into();
    cfg["tun_name"] = tun_name.clone().into();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let path = match write_config(&path, cfg) {
        Ok(()) => path,
        Err(e) => {
            let alt = PathBuf::from("fluxpeer-node.json");
            eprintln!(
                "! could not write {} ({e}); falling back to {}",
                path.display(),
                alt.display()
            );
            write_config(&alt, cfg)?;
            alt
        }
    };
    println!("{}", enrollment_message(&name, cfg["device_id"].as_str().unwrap_or(""), &address, &path));
    Ok((path, tun_name))
}

/// Enroll without writing credentials. Daemon callers supply their own confined
/// persistence policy; CLI output/fallback behavior stays in enroll_and_write.
pub(crate) async fn enroll_config(token: &str, name: Option<String>) -> std::io::Result<serde_json::Value> {
    Ok(enroll(token, name).await?.config)
}

struct Enrollment { config: serde_json::Value, name: String, address: String }

fn enrollment_message(name: &str, device_id: &str, address: &str, path: &std::path::Path) -> String {
    format!("✓ enrolled as \"{name}\" — device {device_id}, overlay {address}; config {}", path.display())
}

async fn enroll(token: &str, name: Option<String>) -> std::io::Result<Enrollment> {
    let JoinToken { ctrl, code } = decode_token(token)?;
    let name = name.unwrap_or_else(default_name);

    // enroll derives the public key + ECDH proof-of-possession from the private key.
    let (priv_hex, _pub_hex) = keypair()?;
    let client = Client::new(ctrl.clone());
    let dev = client
        .enroll(&code, &name, &priv_hex)
        .await
        .map_err(|e| Error::other(format!("enroll failed: {e:#}")))?;
    let device_id = dev["id"]
        .as_str()
        .ok_or_else(|| Error::other("enroll response missing device id"))?
        .to_string();
    // The per-device auth token is returned ONCE at enroll; persist it so the node
    // can authenticate its control-server calls (config pull / endpoints / routes).
    let auth_token = dev["auth_token"].as_str().unwrap_or_default().to_string();

    Ok(Enrollment { config: serde_json::json!({
        "private_key": priv_hex, "device_id": device_id, "control_server": ctrl,
        "auth_token": auth_token, "prefix_len": 24,
    }), name, address: dev["address_v4"].as_str().unwrap_or("(pending)").to_string() })
}

pub async fn join(token: &str, name: Option<String>, out: Option<String>, no_run: bool) -> std::io::Result<()> {
    let JoinToken { ctrl, .. } = decode_token(token)?;
    println!("→ control-server: {ctrl}");
    let dir = config_dir();
    let (path, _) = enroll_and_write(token, name, out, std::path::Path::new(&dir)).await?;

    // bring the tunnel up (default), unless asked not to.
    if no_run {
        println!(
            "Config ready. Run this network:  sudo fluxpeer node run {}",
            path.display()
        );
        println!("Or run ALL your networks at once:  sudo fluxpeer up");
        return Ok(());
    }
    println!("→ bringing this network up (Ctrl-C to stop; `fluxpeer up` runs all networks)…");
    crate::run(&path.to_string_lossy()).await
}

/// Where multi-network membership configs live; `fluxpeer up` runs every `*.json`.
/// Unix: `/etc/fluxpeer`. Windows: `%PROGRAMDATA%\fluxpeer` (e.g. `C:\ProgramData\fluxpeer`).
pub fn config_dir() -> String {
    #[cfg(unix)]
    return "/etc/fluxpeer".to_string();
    #[cfg(windows)]
    return std::env::var("PROGRAMDATA")
        .map(|p| format!("{p}\\fluxpeer"))
        .unwrap_or_else(|_| "C:\\ProgramData\\fluxpeer".to_string());
}

/// Pick the next free `fpN` tun + `41820+N` port + `<dir>/fpN.json` path, scanning
/// existing configs so a new network doesn't collide with ones already joined.
pub(crate) fn assign_slot(dir: &std::path::Path) -> (PathBuf, String, u16) {
    let mut used = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Ok(s) = std::fs::read_to_string(e.path())
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
                && let Some(n) = v["tun_name"]
                    .as_str()
                    .and_then(|t| t.strip_prefix("fp"))
                    .and_then(|x| x.parse::<u32>().ok())
            {
                used.insert(n);
            }
        }
    }
    let n = (0u32..).find(|i| !used.contains(i)).unwrap_or(0);
    (dir.join(format!("fp{n}.json")), format!("fp{n}"), 41820 + n as u16)
}

fn write_config(path: &std::path::Path, cfg: &serde_json::Value) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(serde_json::to_string_pretty(cfg).unwrap_or_default().as_bytes())?;
    f.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_message_preserves_plain_device_name_and_overlay_address() {
        let message = enrollment_message("work laptop", "dev-7", "100.72.16.7", std::path::Path::new("member.json"));
        assert_eq!(message, "✓ enrolled as \"work laptop\" — device dev-7, overlay 100.72.16.7; config member.json");
        assert!(!message.contains("\\\""));
    }

    #[cfg(unix)]
    #[test]
    fn cli_credential_file_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        let cfg = serde_json::json!({"private_key":"fixture", "auth_token":"fixture-token"});
        write_config(&path, &cfg).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap()).unwrap(), cfg);
    }
}

#[cfg(test)]
mod credential_boundary_tests {
    use super::*;

    #[test]
    fn join_and_enroll_never_send_environment_or_explicit_admin_credentials() {
        const CHILD: &str = "FLUXPEER_T0037_CREDENTIAL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "join::credential_boundary_tests::join_and_enroll_never_send_environment_or_explicit_admin_credentials", "--nocapture"])
                .env(CHILD, "1").env("FLUXPEER_ADMIN_PASSWORD", "test-admin-secret")
                .output().unwrap();
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        }
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            use axum::{routing::post, Json, Router};
            use base64::Engine;
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            let challenge_tx = tx.clone();
            let router = Router::new()
                .route("/api/v1/enroll/challenge", post(move |headers: axum::http::HeaderMap| {
                    let tx = challenge_tx.clone();
                    async move {
                        tx.send(headers).await.unwrap();
                        Json(serde_json::json!({"challenge_id": "c1", "server_pub": "55".repeat(32)}))
                    }
                }))
                .route("/api/v1/enroll", post(move |headers: axum::http::HeaderMap| {
                    let tx = tx.clone();
                    async move {
                        tx.send(headers).await.unwrap();
                        Json(serde_json::json!({"id": "d1", "auth_token": "device-only", "address_v4": "10.1.0.2"}))
                    }
                }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::json!({"ctrl": origin, "code": "invite-only"}).to_string());
            let config = enroll_config(&format!("fp://join/{token}"), Some("test".into())).await.unwrap();
            assert_eq!(config["control_server"], origin);
            assert_eq!(config["auth_token"], "device-only");
            for client in [Client::new(&origin), Client::with_password(&origin, "explicit-admin-secret")] {
                client.enroll("invite-only", "test", &"11".repeat(32)).await.unwrap();
            }
            for _ in 0..6 {
                let headers = rx.recv().await.unwrap();
                assert!(!headers.contains_key("authorization"), "enrollment leaked credentials");
            }
            server.abort();
        });
    }
}
