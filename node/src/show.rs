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
    if json {
        // Serialize once: even zero or multiple interfaces are one JSON value.
        println!("{}", status_array(&paths).await?);
        return Ok(());
    }
    if paths.is_empty() { return Err(std::io::Error::other("no fluxpeer node running")); }
    for path in paths {
        let body = read_status(&path).await?;
        let value = serde_json::from_str(&body).map_err(std::io::Error::other)?;
        print_human(&value);
    }
    Ok(())
}

async fn status_array(paths: &[PathBuf]) -> std::io::Result<serde_json::Value> {
    let mut values = Vec::new();
    for path in paths {
        let body = tokio::time::timeout(std::time::Duration::from_secs(2), read_status(path)).await.map_err(std::io::Error::other)??;
        let value: serde_json::Value = serde_json::from_str(&body).map_err(std::io::Error::other)?;
        if !value.is_object() { return Err(std::io::Error::other("status must be an object")); }
        values.push(value);
    }
    Ok(values.into())
}

/// Aggregate every running network's status as a JSON array (one object per
/// interface) — used by the daemon's `status` command for the desktop GUI.
pub(crate) async fn aggregate_status() -> serde_json::Value {
    let mut arr = Vec::new();
    for path in all_sockets() {
        if let Ok(body) = read_status(&path).await
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
        { arr.push(value); }
    }
    serde_json::Value::Array(arr)
}

pub(crate) async fn read_status(path: &std::path::Path) -> std::io::Result<String> {
    match connect_status(path).await {
        Ok(mut stream) => {
            stream.write_all(b"get-json\n").await?;
            let mut body = String::new();
            stream.read_to_string(&mut body).await?;
            Ok(body)
        }
        Err(error) => crate::statusd::read_failure(path).map(|value| value.to_string()).ok_or(error),
    }
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
pub(crate) fn all_sockets() -> Vec<PathBuf> {
    socket_paths_in(status_dirs(), false).unwrap_or_default()
}

/// Admission checks must propagate directory scan errors instead of assuming
/// there are no other members. Individual endpoint failures are handled later.
pub(crate) fn try_all_sockets() -> std::io::Result<Vec<PathBuf>> {
    socket_paths_in(status_dirs(), true)
}

fn socket_paths_in(dirs: Vec<PathBuf>, strict: bool) -> std::io::Result<Vec<PathBuf>> {
    let ext = if cfg!(windows) { "port" } else { "sock" };
    let mut out = Vec::new();
    for dir in dirs {
        match std::fs::read_dir(&dir) {
            Ok(rd) => for entry in rd {
                let e = match entry {
                    Ok(entry) => entry,
                    Err(error) if strict => return Err(error),
                    Err(_) => continue,
                };
                if e.path().extension().is_some_and(|x| x == ext) {
                    out.push(e.path());
                } else if e.path().extension().is_some_and(|x| x == "error") {
                    out.push(e.path().with_extension(ext));
                }
            },
            // An optional platform directory may not exist until a node starts.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) if strict => return Err(error),
            Err(_) => {},
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
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
    if let Some(error) = i.get("last_error").filter(|e| !e.is_null()) {
        println!("  apply error: {error}");
    }
    if i["restart_required"].as_bool() == Some(true) { println!("  restart required: MTU changed"); }
    for p in v["peers"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        println!();
        println!("peer: {}", p["public_key"].as_str().unwrap_or("?"));
        let transport = p["transport"].as_str().unwrap_or("—");
        match p["endpoint"].as_str() {
            Some(ep) => println!("  endpoint: {ep}  ({transport})"),
            None => println!("  endpoint: (none)  ({transport})"),
        }
        let ips: Vec<&str> = p["allowed_ips"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        println!(
            "  allowed ips: {}",
            if ips.is_empty() {
                "(none)".to_string()
            } else {
                ips.join(", ")
            }
        );
        println!(
            "  latest handshake: {}",
            ago(p["last_handshake_unix"].as_u64().unwrap_or(0))
        );
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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

#[cfg(test)]
mod stopped_tests {
    use super::*;

    #[test]
    fn strict_socket_scan_propagates_directory_errors_and_allows_absent_optional_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let ext = if cfg!(windows) { "port" } else { "sock" };
        let endpoint = dir.path().join("fp0").with_extension(ext);
        std::fs::write(&endpoint, "fixture").unwrap();
        std::fs::write(endpoint.with_extension("error"), "fixture").unwrap();
        let absent = dir.path().join("not-created");
        assert_eq!(socket_paths_in(vec![absent, dir.path().to_owned()], true).unwrap().as_slice(), std::slice::from_ref(&endpoint));
        // A regular file as the scan root fails deterministically even as root.
        let expected = std::fs::read_dir(&endpoint).unwrap_err().kind();
        assert_eq!(socket_paths_in(vec![endpoint.clone()], true).unwrap_err().kind(), expected);
        assert!(socket_paths_in(vec![endpoint], false).unwrap().is_empty());
    }

    #[tokio::test]
    async fn show_and_daemon_status_read_failure_after_the_socket_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fp0.sock");
        let value = serde_json::json!({"interface":{"name":"fp0","up":false,"last_error":"HTTP 403"},"peers":[]});
        std::fs::write(path.with_extension("error"), value.to_string()).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&read_status(&path).await.unwrap()).unwrap();
        assert_eq!(actual, value);
        std::fs::remove_file(path.with_extension("error")).unwrap();
        assert!(read_status(&path).await.is_err());
    }
}

#[cfg(test)]
mod aggregate_tests {
    use super::*;
    #[tokio::test]
    async fn json_is_one_array_for_zero_one_or_two_interfaces_and_errors_propagate() {
        let dir = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for n in 0..=2 {
            let value = status_array(&paths).await.unwrap();
            assert_eq!(value.as_array().unwrap().len(), n);
            let serialized = value.to_string();
            let mut stream = serde_json::Deserializer::from_str(&serialized).into_iter::<serde_json::Value>();
            assert_eq!(stream.next().unwrap().unwrap(), value);
            assert!(stream.next().is_none());
            let path = dir.path().join(format!("fp{n}.sock"));
            std::fs::write(path.with_extension("error"), serde_json::json!({"interface":{"name":format!("fp{n}"),"up":false},"peers":[]}).to_string()).unwrap();
            paths.push(path);
        }
        std::fs::write(paths[0].with_extension("error"), "invalid JSON").unwrap();
        assert!(status_array(&paths).await.is_err());
    }
}
