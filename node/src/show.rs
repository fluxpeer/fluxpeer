//! `fluxpeer show` — fluxpeer's `wg show`. Queries the node-local status socket
//! and prints a `wg show`-style table, plus the mesh columns wg can't model
//! (transport rung, rtt). `--json` dumps the raw status.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::statusd::socket_path;

pub async fn show(iface: Option<String>, json: bool) -> std::io::Result<()> {
    let paths = match iface {
        Some(i) => vec![socket_path(&i)],
        None => all_sockets(),
    };
    if paths.is_empty() {
        return Err(std::io::Error::other(
            "no fluxpeer node running (no status socket). `fluxpeer up` or `fluxpeer join <token>` first.",
        ));
    }
    // Aggregate every running network interface (one device may be in many).
    for (i, path) in paths.iter().enumerate() {
        if i > 0 {
            println!();
        }
        if let Err(e) = show_one(path, json).await {
            eprintln!("! {}: {e}", path.display());
        }
    }
    Ok(())
}

async fn show_one(path: &std::path::Path, json: bool) -> std::io::Result<()> {
    let mut stream = connect_status(path)
        .await
        .map_err(|e| std::io::Error::other(format!("{} ({e})", path.display())))?;
    stream.write_all(b"get-json\n").await?;
    let mut body = String::new();
    stream.read_to_string(&mut body).await?;
    if json {
        println!("{body}");
        return Ok(());
    }
    let v: serde_json::Value = serde_json::from_str(&body).map_err(std::io::Error::other)?;
    print_human(&v);
    Ok(())
}

/// Aggregate every running network's status as a JSON array (one object per
/// interface) — used by the daemon's `status` command for the desktop GUI.
pub(crate) async fn aggregate_status() -> serde_json::Value {
    let mut arr = Vec::new();
    for path in all_sockets() {
        if let Ok(mut s) = connect_status(&path).await {
            let _ = s.write_all(b"get-json\n").await;
            let mut body = String::new();
            if s.read_to_string(&mut body).await.is_ok()
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
            {
                arr.push(v);
            }
        }
    }
    serde_json::Value::Array(arr)
}

/// Connect to a per-iface status endpoint. Unix dials the unix socket directly;
/// Windows reads the published TCP port from the `.port` file and dials loopback.
#[cfg(unix)]
async fn connect_status(path: &std::path::Path) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(path).await
}
#[cfg(windows)]
async fn connect_status(path: &std::path::Path) -> std::io::Result<tokio::net::TcpStream> {
    let port: u16 = std::fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|_| std::io::Error::other("bad status port file"))?;
    tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await
}

/// Status-endpoint dirs to scan for running networks.
fn status_dirs() -> Vec<PathBuf> {
    #[cfg(unix)]
    return vec![PathBuf::from("/run/fluxpeer"), PathBuf::from("/tmp/fluxpeer")];
    #[cfg(windows)]
    return vec![crate::statusd::status_dir()];
}

/// Every running network's status endpoint (`*.sock` on unix, `*.port` on Windows).
fn all_sockets() -> Vec<PathBuf> {
    let ext = if cfg!(windows) { "port" } else { "sock" };
    let mut out = Vec::new();
    for dir in status_dirs() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                if e.path().extension().is_some_and(|x| x == ext) {
                    out.push(e.path());
                }
            }
        }
    }
    out.sort();
    out
}

/// `fluxpeer networks` — list the networks this device has joined (config dir) +
/// whether each is currently up (its status socket exists).
pub fn list_networks(dir: &str) -> std::io::Result<()> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        println!("no networks joined ({dir}). `fluxpeer join <token>` first.");
        return Ok(());
    };
    let mut rows = Vec::new();
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().is_some_and(|x| x == "json")
            && let Ok(s) = std::fs::read_to_string(&path)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
        {
            let tun = v["tun_name"].as_str().unwrap_or("?").to_string();
            let ctrl = v["control_server"].as_str().unwrap_or("?").to_string();
            let up = socket_path(&tun).exists();
            rows.push((tun, ctrl, up));
        }
    }
    if rows.is_empty() {
        println!("no networks joined. `fluxpeer join <token>` first.");
        return Ok(());
    }
    rows.sort();
    println!("{:<6} {:<6} CONTROL-SERVER", "TUN", "STATE");
    for (tun, ctrl, up) in rows {
        println!("{:<6} {:<6} {}", tun, if up { "up" } else { "down" }, ctrl);
    }
    Ok(())
}

fn print_human(v: &serde_json::Value) {
    let i = &v["interface"];
    println!("interface: {}", i["name"].as_str().unwrap_or("?"));
    println!("  public key: {}", i["public_key"].as_str().unwrap_or("?"));
    println!("  listening port: {}", i["listen_port"].as_u64().unwrap_or(0));
    if let Some(a) = i["address"].as_str() {
        println!("  address: {a}");
    }
    if let Some(c) = i["control_server"].as_str() {
        println!("  control: {c}");
    }
    for p in v["peers"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        println!();
        println!("peer: {}", p["public_key"].as_str().unwrap_or("?"));
        let transport = p["transport"].as_str().unwrap_or("—");
        match p["endpoint"].as_str() {
            Some(ep) => println!("  endpoint: {ep}  ({transport})"),
            None => println!("  endpoint: (none)  ({transport})"),
        }
        let ips: Vec<&str> = p["allowed_ips"].as_array().map(Vec::as_slice).unwrap_or(&[]).iter().filter_map(|x| x.as_str()).collect();
        println!("  allowed ips: {}", if ips.is_empty() { "(none)".to_string() } else { ips.join(", ") });
        println!("  latest handshake: {}", ago(p["last_handshake_unix"].as_u64().unwrap_or(0)));
        println!(
            "  transfer: {} received, {} sent",
            human_bytes(p["rx_bytes"].as_u64().unwrap_or(0)),
            human_bytes(p["tx_bytes"].as_u64().unwrap_or(0))
        );
        if let Some(rtt) = p["rtt_ms"].as_f64() {
            println!("  rtt: {rtt:.1} ms");
        }
    }
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut f = n as f64;
    let mut i = 0;
    while f >= 1024.0 && i < U.len() - 1 {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{f:.2} {}", U[i])
    }
}

fn ago(unix: u64) -> String {
    if unix == 0 {
        return "never".to_string();
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let d = now.saturating_sub(unix);
    if d < 60 {
        format!("{d} second{} ago", plural(d))
    } else if d < 3600 {
        let m = d / 60;
        format!("{m} minute{} ago", plural(m))
    } else {
        let h = d / 3600;
        format!("{h} hour{} ago", plural(h))
    }
}

fn plural(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
}
