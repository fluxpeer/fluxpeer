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
    let blob = token
        .trim()
        .strip_prefix("fp://join/")
        .unwrap_or_else(|| token.trim());
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(blob.trim_end_matches('='))
        .map_err(|e| Error::other(format!("invalid join token (base64): {e}")))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| Error::other(format!("invalid join token (json): {e}")))?;
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
/// Shared by the CLI `join` and the daemon's `join` command (which spawns the
/// tunnel itself rather than blocking here).
pub(crate) async fn enroll_and_write(
    token: &str,
    name: Option<String>,
    out: Option<String>,
    dir: &std::path::Path,
) -> std::io::Result<(PathBuf, String)> {
    let JoinToken { ctrl, code } = decode_token(token)?;
    let name = name.unwrap_or_else(default_name);

    let (priv_hex, pub_hex) = keypair();
    let client = Client::new(ctrl.clone());
    let dev = client
        .enroll(&code, &name, &pub_hex)
        .await
        .map_err(|e| Error::other(format!("enroll failed: {e:#}")))?;
    let device_id = dev["id"]
        .as_str()
        .ok_or_else(|| Error::other("enroll response missing device id"))?
        .to_string();
    // The per-device auth token is returned ONCE at enroll; persist it so the node
    // can authenticate its control-server calls (config pull / endpoints / routes).
    let auth_token = dev["auth_token"].as_str().unwrap_or_default().to_string();
    let addr = dev["address_v4"].as_str().unwrap_or("(pending)");

    // Multi-network: each membership is its own config in the config dir with a
    // distinct tun/port (auto-assigned), so one device can be in many networks.
    let (path, tun_name, listen_port) = match out {
        Some(o) => (PathBuf::from(o), "fp0".to_string(), 41820u16),
        None => assign_slot(dir),
    };
    let cfg = serde_json::json!({
        "private_key": priv_hex,
        "device_id": device_id,
        "control_server": ctrl,
        "auth_token": auth_token,
        "listen_port": listen_port,
        "tun_name": tun_name,
        "prefix_len": 24,
    });
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let path = match write_config(&path, &cfg) {
        Ok(()) => path,
        Err(e) => {
            let alt = PathBuf::from("fluxpeer-node.json");
            eprintln!("! could not write {} ({e}); falling back to {}", path.display(), alt.display());
            write_config(&alt, &cfg)?;
            alt
        }
    };
    println!("✓ enrolled as \"{name}\" — device {device_id}, overlay {addr}; config {}", path.display());
    Ok((path, tun_name))
}

pub async fn join(token: &str, name: Option<String>, out: Option<String>, no_run: bool) -> std::io::Result<()> {
    let JoinToken { ctrl, .. } = decode_token(token)?;
    println!("→ control-server: {ctrl}");
    let dir = config_dir();
    let (path, _) = enroll_and_write(token, name, out, std::path::Path::new(&dir)).await?;

    // bring the tunnel up (default), unless asked not to.
    if no_run {
        println!("Config ready. Run this network:  sudo fluxpeer node run {}", path.display());
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
                && let Some(n) = v["tun_name"].as_str().and_then(|t| t.strip_prefix("fp")).and_then(|x| x.parse::<u32>().ok())
            {
                used.insert(n);
            }
        }
    }
    let n = (0u32..).find(|i| !used.contains(i)).unwrap_or(0);
    (dir.join(format!("fp{n}.json")), format!("fp{n}"), 41820 + n as u16)
}

fn write_config(path: &std::path::Path, cfg: &serde_json::Value) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(serde_json::to_string_pretty(cfg).unwrap_or_default().as_bytes())?;
    f.write_all(b"\n")
}
