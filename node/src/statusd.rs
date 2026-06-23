//! Node-local status socket — fluxpeer's analogue of WireGuard's UAPI socket.
//!
//! wg's `wg show` reads live state from `/var/run/wireguard/<iface>.sock` (or
//! kernel netlink). We expose the same idea at `/run/fluxpeer/<iface>.sock`:
//!
//! - `get=1\n\n` → the **wg UAPI** get format (hex keys, rx/tx/handshake), so the
//! stock `wg` tool works against a fluxpeer iface;
//! - anything else → richer **fluxpeer JSON** (adds transport rung + rtt), which
//! `fluxpeer show` formats.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(windows)]
use tokio::net::TcpListener;

use crate::status::{self, StatusRegistry};

/// Base dir for status endpoints. Unix mirrors wg's `/var/run/wireguard`
/// (`/run/fluxpeer`, `/tmp` fallback); Windows uses `%LOCALAPPDATA%\fluxpeer`.
pub(crate) fn status_dir() -> PathBuf {
    #[cfg(unix)]
    return PathBuf::from(if std::path::Path::new("/run").is_dir() { "/run/fluxpeer" } else { "/tmp/fluxpeer" });
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("fluxpeer");
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    sock_path: PathBuf,
    reg: StatusRegistry,
    own_priv_hex: String,
    own_pub_hex: String,
    iface: String,
    listen_port: u16,
    address: Ipv4Addr,
    control_server: String,
) {
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
                Ok((stream, _)) => handle(stream, &reg, &own_priv_hex, &own_pub_hex, &iface, listen_port, address, &control_server).await,
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
                Ok((stream, _)) => handle(stream, &reg, &own_priv_hex, &own_pub_hex, &iface, listen_port, address, &control_server).await,
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
    own_priv_hex: &str,
    own_pub_hex: &str,
    iface: &str,
    listen_port: u16,
    address: Ipv4Addr,
    control_server: &str,
) {
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let resp = if req.starts_with("get=") {
        wg_uapi_get(reg, own_priv_hex, listen_port)
    } else {
        json_status(reg, own_pub_hex, iface, listen_port, address, control_server)
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
    own_pub_hex: &str,
    iface: &str,
    listen_port: u16,
    address: Ipv4Addr,
    control_server: &str,
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
                "tx_bytes": p.tx_bytes,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "interface": {
            "name": iface,
            "public_key": own_pub_hex,
            "listen_port": listen_port,
            "address": address.to_string(),
            "control_server": control_server,
            "peers": peers.len(),
        },
        "peers": peers,
    });
    serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
}
