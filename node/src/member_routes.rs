// SPDX-License-Identifier: BSD-3-Clause
//! Manage pending routes with one membership's device credential, without a TUN.
use std::{io::{self, Read}, path::Path, time::Duration};
use serde_json::{Value, json};

#[derive(serde::Deserialize)]
struct Membership {
    tun_name: String,
    device_id: String,
    control_server: String,
    auth_token: Option<String>,
}

enum Action<'a> { List, Advertise(&'a str), Withdraw(&'a str) }

/// Read this member's authoritative route approval state from control.
pub async fn list(dir: &str, iface: &str) -> io::Result<Value> { request(dir, iface, Action::List).await }
/// Register a pending prefix. Repeating an existing advertisement is idempotent.
pub async fn advertise(dir: &str, iface: &str, prefix: &str) -> io::Result<Value> { request(dir, iface, Action::Advertise(prefix)).await }
/// Withdraw a pending prefix. Approved routes require administrator removal.
pub async fn unadvertise(dir: &str, iface: &str, prefix: &str) -> io::Result<Value> { request(dir, iface, Action::Withdraw(prefix)).await }

async fn request(dir: &str, iface: &str, action: Action<'_>) -> io::Result<Value> {
    let prefix = match action {
        Action::List => None,
        Action::Advertise(prefix) | Action::Withdraw(prefix) => Some(prefix.parse::<fluxpeer_sdk::prefix::IpPrefix>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?.to_string()),
    };
    let path = crate::daemon::member_config(Path::new(dir), iface)?;
    let mut options = std::fs::OpenOptions::new(); options.read(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK); }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() { return Err(io::Error::other("membership must be a regular file")); }
    let mut raw = String::new(); file.read_to_string(&mut raw)?;
    let cfg: Membership = serde_json::from_str(&raw).map_err(io::Error::other)?;
    if cfg.tun_name != iface || cfg.device_id.is_empty() { return Err(io::Error::other("membership identity mismatch")); }
    let token = cfg.auth_token.as_deref().filter(|v| !v.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "membership has no device token; re-enroll this device"))?;
    let client = fluxpeer_sdk::Client::with_password(&cfg.control_server, token);
    let routes = tokio::time::timeout(Duration::from_secs(10), async {
        match (action, prefix.as_deref()) {
            (Action::Advertise(_), Some(prefix)) => client.request_device_route(&cfg.device_id, prefix).await,
            (Action::Withdraw(_), Some(prefix)) => client.withdraw_device_route(&cfg.device_id, prefix).await,
            _ => client.list_device_routes(&cfg.device_id).await,
        }
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control route request timed out"))?
        .map_err(|e| io::Error::other(e.to_string()))?;
    if !routes.is_array() { return Err(io::Error::other("control returned invalid route state")); }
    Ok(json!({"ok":true,"iface":iface,"device_id":cfg.device_id,"control":cfg.control_server,"routes":routes}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn member_routes_uses_selected_token_and_control_without_local_writes() {
        let store = Arc::new(fluxpeer_control_server::sql_store::SqlStore::connect("sqlite::memory:").await.unwrap());
        let net = store.create_network("routes").await.unwrap();
        let invite = store.create_invite(&net.id, None, None).await.unwrap();
        let (a, token_a) = store.enroll(&invite.code, "a", &hex::encode([71;32]), 0).await.unwrap();
        let (b, token_b) = store.enroll(&invite.code, "b", &hex::encode([72;32]), 0).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = format!("http://{}", listener.local_addr().unwrap());
        let router = fluxpeer_control_server::sql_router(store.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap(); let root = dir.path().to_str().unwrap();
        // Legacy OpenWrt node.json remains supported until the T-0048 migration.
        let config = json!({"tun_name":"fp0","device_id":a.id,"control_server":control,"auth_token":token_a});
        std::fs::write(dir.path().join("node.json"), config.to_string()).unwrap();
        let second = json!({"tun_name":"fp1","device_id":b.id,"control_server":control,"auth_token":token_b});
        std::fs::write(dir.path().join("fp1.json"), second.to_string()).unwrap();
        let result = advertise(root, "fp1", "192.168.9.1/24").await.unwrap();
        assert_eq!(result["device_id"], b.id); assert_eq!(result["control"], control);
        assert_eq!(result["routes"][0]["approved"], false);
        assert!(list(root, "fp0").await.unwrap()["routes"].as_array().unwrap().is_empty());
        assert_eq!(list(root, "fp1").await.unwrap(), result);
        assert!(unadvertise(root, "fp1", "192.168.9.0/24").await.unwrap()["routes"].as_array().unwrap().is_empty());
        assert!(advertise(root, "../fp0", "10.0.0.0/8").await.is_err());
        assert!(advertise(root, "fp0", "invalid").await.is_err());
        assert_eq!(std::fs::read_to_string(dir.path().join("node.json")).unwrap(), config.to_string());
        assert_eq!(std::fs::read_to_string(dir.path().join("fp1.json")).unwrap(), second.to_string());
        let mut wrong = config.clone(); wrong["auth_token"] = json!(token_b);
        std::fs::write(dir.path().join("node.json"), wrong.to_string()).unwrap();
        assert!(advertise(root, "fp0", "10.0.0.0/8").await.unwrap_err().to_string().contains("403"));
        wrong["auth_token"] = Value::Null;
        std::fs::write(dir.path().join("node.json"), wrong.to_string()).unwrap();
        assert!(list(root, "fp0").await.unwrap_err().to_string().contains("no device token"));
        assert!(!result.to_string().contains(&token_b));
        server.abort();
    }
}
