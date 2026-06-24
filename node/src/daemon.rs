//! The node daemon (`fluxpeer up`): runs every joined network at once + a local
//! control API the desktop GUI drives — status / networks / join / connect /
//! disconnect.
//!
//! IPC is **localhost TCP + a token** (not a unix socket): tokio's `UnixListener`
//! is unix-only, and this must run identically on Linux, macOS AND Windows. The
//! token is a CSPRNG string written to `<config-dir>/daemon.token` (readable only
//! by the user running the daemon); the GUI reads it and sends it with every
//! command, so other local processes can't drive the tunnels.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

/// Default loopback control endpoint for the GUI ↔ daemon.
pub const DAEMON_ADDR: &str = "127.0.0.1:41999";

struct Daemon {
    dir: PathBuf,
    token: String,
    // iface → child process (`fluxpeer node run <cfg>`). A child process — not an
    // in-process task — because the node's run() fans out many detached tasks
    // (workers, relay, tcp-direct, statusd) that aborting a JoinHandle can't reach;
    // killing the process lets the OS reclaim the TUN, sockets and ports cleanly.
    nets: Mutex<HashMap<String, Child>>,
}

fn admin_api_allowed() -> bool {
    std::env::var("FLUXPEER_ALLOW_ADMIN_API").as_deref() == Ok("1")
}

fn admin_api_disabled() -> serde_json::Value {
    serde_json::json!({ "error": "admin api disabled" })
}

fn redact_config(mut cfg: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert("private_key".to_string(), serde_json::json!("<redacted>"));
    }
    cfg
}

/// Run the daemon: bring up every config in `dir`, then serve the control API.
pub async fn daemon(dir: String, addr: Option<String>) -> std::io::Result<()> {
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).ok();
    let token = ensure_token(&dir)?;
    let d = Arc::new(Daemon {
        dir: dir.clone(),
        token,
        nets: Mutex::new(HashMap::new()),
    });
    for cfg in configs(&dir) {
        d.spawn_net(&cfg);
    }
    let addr = addr.unwrap_or_else(|| DAEMON_ADDR.to_string());
    let listener = TcpListener::bind(&addr).await?;
    println!(
        "→ fluxpeer daemon: {} network(s) up; control API on {addr}",
        d.nets.lock().len()
    );
    loop {
        let (stream, _) = listener.accept().await?;
        let d = d.clone();
        tokio::spawn(async move {
            let _ = d.handle(stream).await;
        });
    }
}

/// Update `exit_node` in every membership config under `dir`.
pub fn set_exit(dir: &str, enabled: bool) -> std::io::Result<usize> {
    let mut updated = 0usize;
    for path in configs(Path::new(dir)) {
        let raw = std::fs::read_to_string(&path)?;
        let mut cfg: serde_json::Value = serde_json::from_str(&raw).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: invalid JSON: {err}", path.display()),
            )
        })?;
        let Some(obj) = cfg.as_object_mut() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: config root is not an object", path.display()),
            ));
        };
        obj.insert("exit_node".to_string(), serde_json::json!(enabled));
        let mut serialized = serde_json::to_string_pretty(&cfg).map_err(std::io::Error::other)?;
        serialized.push('\n');
        std::fs::write(&path, serialized)?;
        updated += 1;
    }
    Ok(updated)
}

impl Daemon {
    /// Spawn a node task for one config (idempotent per interface).
    fn spawn_net(&self, cfg: &Path) {
        let Some(iface) = read_iface(cfg) else { return };
        if self.nets.lock().contains_key(&iface) {
            return;
        }
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("fluxpeer"));
        let p = cfg.to_string_lossy().to_string();
        // Capture the node's tracing output (stderr) to `<dir>/<iface>.log` so the
        // GUI's diagnostics panel can tail it; truncate per run to stay bounded.
        let log_path = self.dir.join(format!("{iface}.log"));
        let log = std::fs::File::create(&log_path).ok();
        let (out, err) = match log {
            Some(f) => match f.try_clone() {
                Ok(f2) => (std::process::Stdio::from(f), std::process::Stdio::from(f2)),
                Err(_) => (std::process::Stdio::null(), std::process::Stdio::null()),
            },
            None => (std::process::Stdio::null(), std::process::Stdio::null()),
        };
        let mut cmd = Command::new(exe);
        cmd.args(["node", "run", &p]).stdout(out).stderr(err).kill_on_drop(true);
        if std::env::var_os("RUST_LOG").is_none() {
            cmd.env("RUST_LOG", "info");
        }
        match cmd.spawn() {
            Ok(child) => {
                self.nets.lock().insert(iface, child);
            }
            Err(e) => tracing::error!(config = %p, error = %e, "failed to start network"),
        }
    }

    /// Stop one network: kill its process and WAIT for it to exit, so the OS
    /// reclaims the TUN (the fd closes → the non-persistent device is removed),
    /// the UDP/listen ports, and every detached task. Then remove the leftover
    /// status socket file and (belt-and-suspenders) any lingering interface.
    async fn stop_iface(&self, iface: &str) {
        let child = self.nets.lock().remove(iface);
        if let Some(mut c) = child {
            // Graceful first: SIGTERM lets a full-tunnel (exit-node) child restore
            // the default route + DNS before dying. Force-kill only if it doesn't
            // exit promptly. (SIGKILL alone would strand the box's routing.)
            #[cfg(unix)]
            {
                if let Some(pid) = c.id() {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                    }
                }
                if tokio::time::timeout(std::time::Duration::from_secs(3), c.wait())
                    .await
                    .is_err()
                {
                    let _ = c.kill().await;
                }
            }
            #[cfg(not(unix))]
            let _ = c.kill().await; // SIGKILL + reap
        }
        let _ = std::fs::remove_file(crate::statusd::socket_path(iface));
        #[cfg(target_os = "linux")]
        let _ = std::process::Command::new("ip")
            .args(["link", "del", iface])
            .stderr(std::process::Stdio::null()) // device usually already gone with the process
            .status();
    }

    /// Bring every running network down — each `stop_iface` SIGTERMs its node so a
    /// full-tunnel/exit child restores routes + DNS, and a split-tunnel child's TUN
    /// closes (dropping its overlay/intranet routes) — then exit the daemon process.
    /// We reply BEFORE exiting (brief delay so the ack flushes) so the caller knows
    /// teardown is done.
    async fn shutdown(&self) -> serde_json::Value {
        let ifaces: Vec<String> = self.nets.lock().keys().cloned().collect();
        for iface in ifaces {
            self.stop_iface(&iface).await;
        }
        tokio::spawn(async {
            // Let `handle` write the response below before the process dies.
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            std::process::exit(0);
        });
        serde_json::json!({ "ok": true, "shutdown": true })
    }

    async fn handle(&self, stream: TcpStream) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_default();
        let resp = if req["auth"].as_str() != Some(self.token.as_str()) {
            serde_json::json!({ "error": "unauthorized" })
        } else {
            self.dispatch(&req).await
        };
        let mut s = reader.into_inner();
        s.write_all(serde_json::to_string(&resp).unwrap_or_default().as_bytes())
            .await?;
        s.write_all(b"\n").await
    }

    async fn dispatch(&self, req: &serde_json::Value) -> serde_json::Value {
        match req["cmd"].as_str().unwrap_or("") {
            // Live status of every running network (for the GUI dashboard).
            "status" => crate::show::aggregate_status().await,
            // The networks this device has joined + up/down.
            "networks" => self.networks(),
            // Join a new network from an invite token, then bring it up.
            "join" => self.join(req["token"].as_str().unwrap_or("")).await,
            // Connect / disconnect one network without touching the others.
            "up" => self.set_iface(req["iface"].as_str().unwrap_or(""), true).await,
            "down" => self.set_iface(req["iface"].as_str().unwrap_or(""), false).await,
            // Edit this device's own wg settings (mtu/dns/endpoint) — a LOCAL
            // override (no admin needed); restarts that network to apply.
            "settings" => self.settings(req).await,
            // Manual config editing + file import (like WireGuard's edit/import).
            "config" | "get_config" => self.get_config(req["iface"].as_str().unwrap_or("")),
            "set-config" | "set_config" => {
                if admin_api_allowed() {
                    self.set_config(req).await
                } else {
                    admin_api_disabled()
                }
            }
            "import" => {
                if admin_api_allowed() {
                    self.import(req).await
                } else {
                    admin_api_disabled()
                }
            }
            // Leave a network for good: stop it + delete its on-disk config + log.
            "leave" => self.leave(req["iface"].as_str().unwrap_or("")).await,
            // Bring EVERY network down (clean route/DNS teardown) and exit the daemon.
            // The desktop GUI calls this on Quit so closing the app actually
            // disconnects, instead of leaving this (detached) daemon — and its
            // TUN/routes — alive and the overlay/intranet still reachable.
            "shutdown" => {
                if admin_api_allowed() {
                    self.shutdown().await
                } else {
                    admin_api_disabled()
                }
            }
            // Tail a network's node log (for the GUI diagnostics panel).
            "logs" => self.logs(
                req["iface"].as_str().unwrap_or(""),
                req["lines"].as_u64().unwrap_or(200) as usize,
            ),
            other => serde_json::json!({ "error": format!("unknown cmd: {other}") }),
        }
    }

    fn networks(&self) -> serde_json::Value {
        let running = self.nets.lock();
        let mut arr = Vec::new();
        for cfg in configs(&self.dir) {
            if let Ok(s) = std::fs::read_to_string(&cfg)
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
            {
                let iface = v["tun_name"].as_str().unwrap_or("?").to_string();
                arr.push(serde_json::json!({
                    "iface": iface,
                    "control_server": v["control_server"].as_str().unwrap_or(""),
                    "up": running.contains_key(&iface),
                    "exit_node": v["exit_node"].as_bool().unwrap_or(false),
                    "force_relay": v["force_relay"].as_bool().unwrap_or(false),
                    "relay_anytls": v["relay_anytls"].as_bool().unwrap_or(false),
                    "relay_bond": v["relay_bond"].as_bool().unwrap_or(false),
                }));
            }
        }
        serde_json::Value::Array(arr)
    }

    async fn join(&self, token: &str) -> serde_json::Value {
        if token.is_empty() {
            return serde_json::json!({ "error": "missing join token" });
        }
        match crate::join::enroll_and_write(token, None, None, &self.dir).await {
            Ok((path, iface)) => {
                self.spawn_net(&path);
                serde_json::json!({ "ok": true, "iface": iface })
            }
            Err(e) => serde_json::json!({ "error": format!("{e}") }),
        }
    }

    /// Return a network config JSON with the private key redacted. The local
    /// daemon token is enough to operate networks, but must not disclose key
    /// material to API clients.
    fn get_config(&self, iface: &str) -> serde_json::Value {
        let path = self.dir.join(format!("{iface}.json"));
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        {
            Some(cfg) => serde_json::json!({ "iface": iface, "config": redact_config(cfg) }),
            None => serde_json::json!({ "error": "no config for iface" }),
        }
    }

    /// Overwrite a network's config from manually-edited JSON, then restart it.
    async fn set_config(&self, req: &serde_json::Value) -> serde_json::Value {
        let iface = req["iface"].as_str().unwrap_or("");
        let cfg = &req["config"];
        if iface.is_empty() || !cfg.is_object() || cfg["private_key"].as_str().is_none() {
            return serde_json::json!({ "error": "invalid config (need an object with private_key, …)" });
        }
        let path = self.dir.join(format!("{iface}.json"));
        if std::fs::write(&path, serde_json::to_string_pretty(cfg).unwrap_or_default()).is_err() {
            return serde_json::json!({ "error": "write failed" });
        }
        self.restart(iface, &path).await;
        serde_json::json!({ "ok": true, "iface": iface })
    }

    /// Import a network config (from a file the GUI read) as a new network + up it.
    async fn import(&self, req: &serde_json::Value) -> serde_json::Value {
        let cfg = &req["config"];
        if !cfg.is_object() || cfg["private_key"].as_str().is_none() {
            return serde_json::json!({ "error": "not a fluxpeer node config (need private_key, device_id, control_server)" });
        }
        // give it a fresh, non-colliding tun/port slot.
        let (path, tun, port) = crate::join::assign_slot(&self.dir);
        let mut cfg = cfg.clone();
        cfg["tun_name"] = serde_json::json!(tun);
        cfg["listen_port"] = serde_json::json!(port);
        if std::fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap_or_default()).is_err() {
            return serde_json::json!({ "error": "write failed" });
        }
        self.spawn_net(&path);
        serde_json::json!({ "ok": true, "iface": tun })
    }

    /// Leave a network permanently: stop it, then delete its on-disk config + log
    /// so it no longer appears in `networks` and won't auto-start next daemon run.
    /// (Control-server membership is left intact — re-joining just needs the token.)
    async fn leave(&self, iface: &str) -> serde_json::Value {
        if iface.is_empty() {
            return serde_json::json!({ "error": "missing iface" });
        }
        let cfg = self.dir.join(format!("{iface}.json"));
        if !cfg.exists() {
            return serde_json::json!({ "error": format!("no config for {iface}") });
        }
        self.stop_iface(iface).await;
        let _ = std::fs::remove_file(&cfg);
        let _ = std::fs::remove_file(self.dir.join(format!("{iface}.log")));
        serde_json::json!({ "ok": true, "iface": iface, "left": true })
    }

    /// Return the last `lines` of a network's node log (diagnostics panel).
    fn logs(&self, iface: &str, lines: usize) -> serde_json::Value {
        if iface.is_empty() {
            return serde_json::json!({ "error": "missing iface" });
        }
        let path = self.dir.join(format!("{iface}.log"));
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return serde_json::json!({ "iface": iface, "log": "" });
        };
        let n = lines.clamp(1, 2000);
        let tail: Vec<&str> = raw.lines().rev().take(n).collect();
        let joined: String = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
        serde_json::json!({ "iface": iface, "log": strip_ansi(&joined) })
    }

    /// Restart one network (down + up) to apply a config change.
    async fn restart(&self, iface: &str, path: &Path) {
        self.stop_iface(iface).await;
        self.spawn_net(path);
    }

    /// Edit a network's own wg settings in its local config + restart it to apply.
    async fn settings(&self, req: &serde_json::Value) -> serde_json::Value {
        let iface = req["iface"].as_str().unwrap_or("");
        if iface.is_empty() {
            return serde_json::json!({ "error": "missing iface" });
        }
        let path = self.dir.join(format!("{iface}.json"));
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return serde_json::json!({ "error": "no config for iface" });
        };
        let Ok(mut cfg) = serde_json::from_str::<serde_json::Value>(&raw) else {
            return serde_json::json!({ "error": "bad config" });
        };
        if req.get("mtu").is_some() {
            cfg["mtu"] = req["mtu"].clone();
        }
        if req.get("dns").is_some() {
            cfg["dns"] = req["dns"].clone();
        }
        if let Some(ep) = req.get("endpoint").and_then(|x| x.as_str()) {
            cfg["advertise"] = if ep.is_empty() {
                serde_json::json!([])
            } else {
                serde_json::json!([ep])
            };
        }
        // Split-tunnel exclude CIDRs (only meaningful under a full-tunnel exit peer):
        // an empty array clears them, so the field round-trips faithfully.
        if req.get("exclude_routes").is_some() {
            cfg["exclude_routes"] = req["exclude_routes"].clone();
        }
        // Advertise THIS device as an exit node (IP forward + NAT). Off by default.
        if let Some(ex) = req.get("exit_node").and_then(|x| x.as_bool()) {
            cfg["exit_node"] = serde_json::json!(ex);
        }
        // Connection mode (transport policy): force-relay + relay flavor.
        for k in ["force_relay", "relay_anytls", "relay_bond"] {
            if let Some(b) = req.get(k).and_then(|x| x.as_bool()) {
                cfg[k] = serde_json::json!(b);
            }
        }
        if std::fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap_or_default()).is_err() {
            return serde_json::json!({ "error": "write failed" });
        }
        self.restart(iface, &path).await; // MTU/DNS/endpoint take effect on restart
        serde_json::json!({ "ok": true, "iface": iface })
    }

    /// Connect (`up=true`) or disconnect (`up=false`) one network.
    async fn set_iface(&self, iface: &str, up: bool) -> serde_json::Value {
        if iface.is_empty() {
            return serde_json::json!({ "error": "missing iface" });
        }
        if up {
            let cfg = self.dir.join(format!("{iface}.json"));
            if !cfg.exists() {
                return serde_json::json!({ "error": format!("no config for {iface}") });
            }
            // Defensive: make sure any prior task for this iface is fully stopped
            // (and its device/port released) before recreating it.
            self.stop_iface(iface).await;
            self.spawn_net(&cfg);
        } else {
            self.stop_iface(iface).await;
        }
        serde_json::json!({ "ok": true, "iface": iface, "up": up })
    }
}

/// Strip ANSI CSI escape sequences (`\x1b[ … m` etc.) so the GUI log tail is clean
/// even if a line was written with colour enabled.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // consume until the final byte of the sequence (a letter), inclusive.
            for n in chars.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Every `*.json` membership config in the dir (excludes the token file).
fn configs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "json") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn read_iface(cfg: &Path) -> Option<String> {
    let s = std::fs::read_to_string(cfg).ok()?;
    let v: serde_json::Value = serde_json::from_str(&s).ok()?;
    v["tun_name"].as_str().map(String::from)
}

/// Load (or create) the daemon control token from `<dir>/daemon.token`.
fn ensure_token(dir: &Path) -> std::io::Result<String> {
    let path = dir.join("daemon.token");
    if let Ok(t) = std::fs::read_to_string(&path)
        && t.trim().len() >= 16
    {
        return Ok(t.trim().to_string());
    }
    // CSPRNG bearer token, cross-platform via getrandom (no /dev/urandom, which
    // is absent on Windows; the old time/pid fallback was guessable).
    let mut buf = [0u8; 24];
    getrandom::getrandom(&mut buf).expect("OS CSPRNG (getrandom) failed");
    let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}
