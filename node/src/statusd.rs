//! Node-local status socket — fluxpeer's analogue of WireGuard's UAPI socket.
//!
//! wg's `wg show` reads live state from `/var/run/wireguard/<iface>.sock` (or
//! kernel netlink). We expose the same idea at `/run/fluxpeer/<iface>.sock`:
//!
//! - `get=1\n\n` → the **wg UAPI** get format (hex keys, rx/tx/handshake), so the
//!   stock `wg` tool works against a fluxpeer iface;
//! - anything else → richer **fluxpeer JSON** (adds transport rung + rtt), which
//!   `fluxpeer show` formats.

use std::net::Ipv4Addr;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(windows)]
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;

use crate::status::{self, StatusRegistry};

pub(crate) struct Identity {
    pub device_id: String,
    pub control: String,
}

/// Base dir for status endpoints. Unix mirrors wg's `/var/run/wireguard`
/// (`/run/fluxpeer`, `/tmp` fallback); Windows uses `%LOCALAPPDATA%\fluxpeer`.
pub(crate) fn status_dir() -> PathBuf {
    #[cfg(unix)]
    return PathBuf::from(if std::path::Path::new("/run").is_dir() {
        "/run/fluxpeer"
    } else {
        "/tmp/fluxpeer"
    });
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("fluxpeer");
}

/// Per-interface status endpoint. Unix: a `<iface>.sock` unix socket (wg's UAPI
/// model). Windows (no unix sockets): a `<iface>.port` file holding the TCP port
/// of a `127.0.0.1` listener — same discover-by-directory model, TCP transport.
pub(crate) fn socket_path(iface: &str) -> PathBuf {
    #[cfg(unix)]
    let name = format!("{iface}.sock");
    #[cfg(windows)]
    let name = format!("{iface}.port");
    status_dir().join(name)
}

/// A private atomic snapshot survives process exit without keeping a listener alive.
pub(crate) fn record_failure(iface: &str, error: &std::io::Error) -> std::io::Result<()> {
    write_failure(&socket_path(iface), iface, error)
}

fn write_failure(socket: &std::path::Path, iface: &str, error: &std::io::Error) -> std::io::Result<()> {
    use std::io::Write;
    let path = socket.with_extension("error");
    let dir = path.parent().ok_or_else(|| std::io::Error::other("missing status directory"))?;
    std::fs::create_dir_all(dir)?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    let value = serde_json::json!({"interface":{"name":iface, "up":false, "last_error":error.to_string(),
        "terminal_control":crate::control::terminal_control_error(error)}, "peers":[]});
    file.write_all(value.to_string().as_bytes())?;
    file.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub(crate) fn read_failure(socket: &std::path::Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(socket.with_extension("error")).ok()?).ok()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    sock_path: PathBuf,
    reg: StatusRegistry,
    apply_status: crate::apply::SharedStatus,
    own_priv_hex: String,
    own_pub_hex: String,
    iface: String,
    listen_port: u16,
    address: Ipv4Addr,
    identity: Identity,
) {
    let _ = std::fs::remove_file(sock_path.with_extension("error"));
    if let Some(dir) = sock_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(&sock_path); // clear a stale socket
        let listener = match UnixListener::bind(&sock_path) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(path = %sock_path.display(), error = %e, "status socket bind failed; `fluxpeer show` unavailable");
                return;
            }
        };
        // Local + owner-only, like wg's root-only UAPI socket.
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
        tracing::info!(path = %sock_path.display(), "status socket up (fluxpeer show / wg-uapi)");
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    handle(
                        stream,
                        &reg,
                        &apply_status,
                        &own_priv_hex,
                        &own_pub_hex,
                        &iface,
                        listen_port,
                        address,
                        &identity,
                    )
                    .await
                }
                Err(_) => continue,
            }
        }
    }

    #[cfg(windows)]
    {
        let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "status listener bind failed; `fluxpeer show` unavailable");
                return;
            }
        };
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        // Publish the loopback port so `fluxpeer show` can discover this iface.
        let _ = std::fs::write(&sock_path, port.to_string());
        tracing::info!(path = %sock_path.display(), port, "status listener up (fluxpeer show / wg-uapi)");
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    handle(
                        stream,
                        &reg,
                        &apply_status,
                        &own_priv_hex,
                        &own_pub_hex,
                        &iface,
                        listen_port,
                        address,
                        &identity,
                    )
                    .await
                }
                Err(_) => continue,
            }
        }
    }
}

/// Read one request off a status connection and write back the wg-UAPI or JSON
/// reply. Generic over the stream so the unix-socket and TCP paths share logic.
#[allow(clippy::too_many_arguments)]
async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    reg: &StatusRegistry,
    apply_status: &crate::apply::SharedStatus,
    own_priv_hex: &str,
    own_pub_hex: &str,
    iface: &str,
    listen_port: u16,
    address: Ipv4Addr,
    identity: &Identity,
) {
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let resp = if req.starts_with("get=") {
        wg_uapi_get(reg, own_priv_hex, listen_port)
    } else {
        json_status(reg, apply_status, own_pub_hex, iface, listen_port, address, identity)
    };
    let _ = stream.write_all(resp.as_bytes()).await;
}

/// The wg UAPI `get` response (so `wg show <iface>` works). Hex keys; one block
/// per peer; terminated by `errno=0`.
fn wg_uapi_get(reg: &StatusRegistry, own_priv_hex: &str, listen_port: u16) -> String {
    let mut out = String::new();
    out.push_str(&format!("private_key={own_priv_hex}\n"));
    out.push_str(&format!("listen_port={listen_port}\n"));
    out.push_str("fwmark=0\n");
    for p in status::snapshot(reg) {
        out.push_str(&format!("public_key={}\n", hex::encode(p.pubkey)));
        if let Some(ep) = p.endpoint {
            out.push_str(&format!("endpoint={ep}\n"));
        }
        for cidr in &p.allowed_ips {
            out.push_str(&format!("allowed_ip={cidr}\n"));
        }
        out.push_str(&format!("last_handshake_time_sec={}\n", p.last_handshake_unix));
        out.push_str("last_handshake_time_nsec=0\n");
        out.push_str(&format!("rx_bytes={}\n", p.rx_bytes));
        out.push_str(&format!("tx_bytes={}\n", p.tx_bytes));
        out.push_str("persistent_keepalive_interval=0\n");
    }
    out.push_str("errno=0\n\n");
    out
}

/// The fluxpeer-native JSON status (richer than wg: transport rung + rtt).
fn json_status(
    reg: &StatusRegistry,
    apply_status: &crate::apply::SharedStatus,
    own_pub_hex: &str,
    iface: &str,
    listen_port: u16,
    address: Ipv4Addr,
    identity: &Identity,
) -> String {
    let peers: Vec<serde_json::Value> = status::snapshot(reg)
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "public_key": hex::encode(p.pubkey),
                "endpoint": p.endpoint.map(|e| e.to_string()),
                "transport": status::transport_name(p.transport),
                "allowed_ips": p.allowed_ips,
                "last_handshake_unix": p.last_handshake_unix,
                "rtt_ms": if p.rtt_us == 0 { serde_json::Value::Null } else { (p.rtt_us as f64 / 1000.0).into() },
                "rx_bytes": p.rx_bytes,
                "rx_source_drops": p.rx_source_drops,
                "tx_bytes": p.tx_bytes,
            })
        })
        .collect();
    let applied = apply_status.lock();
    let doc = serde_json::json!({
        "interface": {
            "name": iface,
            "public_key": own_pub_hex,
            "listen_port": listen_port,
            "address": address.to_string(),
            "control_server": identity.control,
            "control": identity.control,
            "device_id": identity.device_id,
            "peers": peers.len(),
            "last_error": applied.last_error,
            "applied_epoch": applied.applied_epoch,
            "restart_required": applied.restart_required,
            "self_exit": applied.self_exit,
            "exit_active": applied.exit_active,
        },
        "peers": peers,
    });
    serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_distinguishes_control_approval_from_effective_provider_state() {
        let state: crate::apply::SharedStatus = Default::default();
        for (approved, active) in [(false, false), (true, false), (true, true), (false, true)] {
            { let mut status = state.lock(); status.self_exit = approved; status.exit_active = active; }
            let doc: serde_json::Value = serde_json::from_str(&json_status(&Default::default(), &state, "test", "fp0", 1234, Ipv4Addr::LOCALHOST, &Identity { device_id: "device-test".into(), control: "https://control.example".into() })).unwrap();
            assert_eq!(doc["interface"]["self_exit"], approved);
            assert_eq!(doc["interface"]["exit_active"], active);
        }
    }

    #[test]
    fn json_exposes_command_failure_and_retains_last_successful_epoch() {
        let reg = Default::default();
        let state: crate::apply::SharedStatus = Default::default();
        state.lock().complete(7, Ok(()));
        let error = crate::apply::ApplyError {
            command: vec!["ip".into(), "route".into(), "replace".into()], exit_code: Some(2),
            stderr: "Operation not permitted".into(), kind: std::io::ErrorKind::PermissionDenied,
        };
        state.lock().complete(8, Err(error));
        let render = || serde_json::from_str::<serde_json::Value>(&json_status(&reg, &state, "test", "fp0", 1234, Ipv4Addr::LOCALHOST, &Identity { device_id: "device-test".into(), control: "https://control.example".into() })).unwrap();
        state.lock().restart_required = true;
        let doc = render();
        assert_eq!(doc["interface"]["restart_required"], true);
        assert_eq!(doc["interface"]["device_id"], "device-test");
        assert_eq!(doc["interface"]["control"], "https://control.example");
        assert!(doc["interface"].get("auth_token").is_none());
        assert_eq!(doc["interface"]["applied_epoch"], 7);
        assert_eq!(doc["interface"]["last_error"]["exit_code"], 2);
        assert_eq!(doc["interface"]["last_error"]["stderr"], "Operation not permitted");
        assert_eq!(doc["interface"]["last_error"]["command"][0], "ip");
        state.lock().complete(8, Ok(()));
        assert!(render()["interface"]["last_error"].is_null());
        assert_eq!(render()["interface"]["applied_epoch"], 8);
    }
}

#[cfg(test)]
mod stopped_tests {
    use super::*;
    #[test]
    fn blocked_carrier_error_survives_bootstrap_and_running_json_status() {
        let dir = tempfile::tempdir().unwrap(); let socket = dir.path().join("fp0.sock");
        let error = crate::carriers::blocked("relay.test");
        write_failure(&socket, "fp0", &error).unwrap();
        let stopped = read_failure(&socket).unwrap();
        assert_eq!(stopped["interface"]["last_error"], error.to_string());
        assert_eq!(stopped["interface"]["terminal_control"], false);
        let state: crate::apply::SharedStatus = Default::default();
        state.lock().complete(1, Err(crate::apply::ApplyError::new(&["kill-switch", "DNS"], error.to_string())));
        let reg: StatusRegistry = Default::default();
        let running: serde_json::Value = serde_json::from_str(&json_status(&reg, &state, "test", "fp0", 1234, Ipv4Addr::LOCALHOST, &Identity { device_id: "device-test".into(), control: "https://control.example".into() })).unwrap();
        assert_eq!(running["interface"]["last_error"]["stderr"], error.to_string());
    }

    #[test]
    fn stopped_member_error_survives_exit_in_private_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("fp0.sock");
        let error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "control HTTP 401");
        write_failure(&socket, "fp0", &error).unwrap();
        let snapshot = read_failure(&socket).unwrap();
        assert_eq!(snapshot["interface"]["up"], false);
        assert_eq!(snapshot["interface"]["terminal_control"], true);
        assert_eq!(snapshot["interface"]["last_error"], "control HTTP 401");
        assert_eq!(snapshot["peers"], serde_json::json!([]));
        #[cfg(unix)]
        assert_eq!(std::fs::metadata(socket.with_extension("error")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
