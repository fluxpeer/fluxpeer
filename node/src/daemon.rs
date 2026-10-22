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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

#[path = "daemon_process.rs"]
mod process;
use process::Processes;

/// Default loopback control endpoint for the GUI ↔ daemon.
pub const DAEMON_ADDR: &str = "127.0.0.1:41999";

struct Daemon {
    dir: PathBuf,
    token: String,
    processes: Processes,
    admission: tokio::sync::Mutex<()>,
    guard_root: PathBuf,
    #[cfg(target_os = "macos")]
    pf_base: PathBuf,
    protected_members: parking_lot::Mutex<std::collections::HashSet<String>>,
    exit: tokio::sync::Notify,
    #[cfg(test)]
    remove_link: Option<fn(String) -> crate::apply::Result>,
}

#[cfg(any(target_os = "linux", test))]
async fn cleanup_link_with(
    iface: String, remove: impl FnOnce(String) -> crate::apply::Result + Send + 'static,
) -> crate::apply::Result {
    crate::apply::blocking(move || match remove(iface) {
        // The TUN normally disappears when the member process closes its fd.
        Err(error) if error.exit_code.is_some() && error.missing() => Ok(()),
        result => result,
    }).await
}

fn lifecycle_error(error: std::io::Error) -> serde_json::Value {
    serde_json::json!({"status":if error.kind() == std::io::ErrorKind::WouldBlock { 409 } else { 500 }, "error":error.to_string()})
}

fn config_error(error: std::io::Error) -> serde_json::Value {
    if error.kind() == std::io::ErrorKind::WouldBlock { lifecycle_error(error) } else { invalid_iface(error) }
}
fn other_membership_up(iface: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::WouldBlock, format!("cannot enable kill-switch while membership {iface} is up; disconnect it first"))
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
    let d = Arc::new(Daemon::new(dir.clone(), token));
    for cfg in configs(&dir) {
        if read_iface(&cfg).and_then(|iface| crate::statusd::read_failure(&crate::statusd::socket_path(&iface)))
            .is_some_and(|status| status["interface"]["terminal_control"] == true) { continue; }
        if let Err(error) = d.spawn_net(&cfg) { tracing::error!(%error, "failed to start network"); }
    }
    let addr = addr.unwrap_or_else(|| DAEMON_ADDR.to_string());
    let listener = TcpListener::bind(&addr).await?;
    println!(
        "→ fluxpeer daemon: {} network(s) up; control API on {addr}",
        d.processes.ifaces().len()
    );
    let mut guard_check = tokio::time::interval(crate::firewall::client::CHECK_INTERVAL);
    guard_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = d.exit.notified() => return Ok(()),
            _ = guard_check.tick() => {
                if let Err(error) = crate::apply::blocking(crate::firewall::client::repair_all).await {
                    tracing::warn!(%error, "client kill-switch reconciliation failed");
                }
                continue;
            }
        };
        let d = d.clone();
        tokio::spawn(async move {
            let _ = d.handle(stream).await;
        });
    }
}

/// Validate a `use_exit` mode string: `off`/`auto`/`<64-hex pubkey>`.
/// Returns the canonical string to store (`off` → caller removes the key).
pub(crate) fn normalize_use_exit(mode: &str) -> Result<String, String> {
    let m = mode.trim();
    if m.is_empty() || m == "off" {
        return Ok("off".to_string());
    }
    if m == "auto" {
        return Ok("auto".to_string());
    }
    let lower = m.to_ascii_lowercase();
    if lower.len() == 64 && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(lower);
    }
    Err(format!(
        "invalid use_exit {mode:?}: expected `auto`, `off`, or a 64-char hex peer pubkey"
    ))
}

/// Local force-on or follow-control. Off clears both overrides so an existing
/// veto cannot silently survive returning to control-plane behavior.
pub fn set_exit(dir: &str, enabled: bool) -> std::io::Result<usize> {
    edit_configs(Path::new(dir), None, |obj| {
        obj.remove("exit_veto");
        if enabled { obj.insert("exit_node".into(), serde_json::json!(true)); }
        else { obj.remove("exit_node"); }
    })
}

fn apply_firewall_setting(cfg: &mut serde_json::Value, req: &serde_json::Value) -> Result<(), String> {
    if let Some(value) = req.get("firewall_trust_external") {
        let enabled = value.as_bool().ok_or("firewall_trust_external must be a boolean")?;
        let obj = cfg.as_object_mut().ok_or("config must be an object")?;
        obj.insert("firewall_trust_external".into(), serde_json::json!(enabled));
    }
    Ok(())
}

/// Shared by daemon settings tests without starting a node or touching routing.
fn apply_provider_settings(obj: &mut serde_json::Map<String, serde_json::Value>, req: &serde_json::Value) {
    if let Some(enabled) = req.get("exit_node").and_then(|v| v.as_bool()) {
        obj.remove("exit_veto");
        if enabled { obj.insert("exit_node".into(), serde_json::json!(true)); }
        else { obj.remove("exit_node"); }
    }
    if let Some(veto) = req.get("exit_veto").and_then(|v| v.as_bool()) {
        if veto { obj.insert("exit_veto".into(), serde_json::json!(true)); }
        else { obj.remove("exit_veto"); }
    }
}

/// Explicit provider refusal, separate from the legacy on/off toggle.
pub fn veto_exit(dir: &str) -> std::io::Result<usize> {
    edit_configs(Path::new(dir), None, |obj| {
        obj.remove("exit_node");
        obj.insert("exit_veto".into(), serde_json::json!(true));
    })
}

/// Set `use_exit` (`auto`/`off`/`<pubkey hex>`) in membership configs under
/// `dir` — one interface when `iface` is given, else all of them. `off`
/// removes the key (split-tunnel is the default).
pub fn set_use_exit(dir: &str, iface: Option<&str>, mode: &str) -> std::io::Result<usize> {
    let mode = normalize_use_exit(mode).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    edit_configs(Path::new(dir), iface, |obj| {
        if mode == "off" {
            obj.remove("use_exit");
        } else {
            obj.insert("use_exit".to_string(), serde_json::json!(mode));
        }
    })
}

/// Configure protection locally. Like use-exit, a running member needs restart.
pub fn set_kill_switch(dir: &str, iface: Option<&str>, enabled: bool) -> std::io::Result<usize> {
    edit_configs(Path::new(dir), iface, |obj| { obj.insert("kill_switch".into(), serde_json::json!(enabled)); })
}

/// Apply `edit` to every matching membership config (`*.json`) under `dir` —
/// filtered to one interface when `iface` is given. Returns the edit count.
fn edit_configs(
    dir: &Path,
    iface: Option<&str>,
    edit: impl Fn(&mut serde_json::Map<String, serde_json::Value>),
) -> std::io::Result<usize> {
    edit_configs_with(dir, iface, edit, live_member_ifaces)
}

fn live_member_ifaces() -> std::io::Result<Vec<String>> { live_member_paths(crate::show::all_sockets()) }

fn live_member_paths(paths: Vec<PathBuf>) -> std::io::Result<Vec<String>> {
    let mut up = Vec::new();
    #[cfg(unix)]
    for path in paths {
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(_) => if let Some(iface) = path.file_stem().and_then(|name| name.to_str()) { up.push(iface.to_string()); },
            Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {},
            Err(error) => return Err(error),
        }
    }
    #[cfg(windows)]
    for path in paths {
        let port: u16 = std::fs::read_to_string(&path)?.trim().parse().map_err(std::io::Error::other)?;
        if std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), std::time::Duration::from_secs(1)).is_ok()
            && let Some(iface) = path.file_stem().and_then(|name| name.to_str()) { up.push(iface.to_string()); }
    }
    Ok(up)
}

fn edit_configs_with(
    dir: &Path, iface: Option<&str>, edit: impl Fn(&mut serde_json::Map<String, serde_json::Value>),
    live: impl FnOnce() -> std::io::Result<Vec<String>>,
) -> std::io::Result<usize> {
    let mut prepared = Vec::new();
    for path in configs(dir) {
        if let Some(want) = iface
            && read_iface(&path).as_deref() != Some(want)
        {
            continue;
        }
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
        let was_enabled = obj.get("kill_switch").is_some_and(|value| value == true);
        edit(obj);
        let enabling = cfg["kill_switch"] == true && (!was_enabled || crate::firewall::client::requested(true, cfg["use_exit"].as_str()));
        prepared.push((path, cfg, enabling));
    }
    if prepared.iter().any(|(_, _, enabling)| *enabling) {
        let up = live()?;
        for (_, cfg, enabling) in &prepared {
            if *enabling
                && let Some(other) = up.iter().find(|other| cfg["tun_name"].as_str() != Some(other.as_str())) {
                return Err(other_membership_up(other));
            }
        }
    }
    for (_, cfg, _) in &prepared { crate::firewall::client::validate_config(cfg)?; }
    let updated = prepared.len();
    for (path, cfg, _) in prepared {
        let mut serialized = serde_json::to_string_pretty(&cfg).map_err(std::io::Error::other)?;
        serialized.push('\n');
        open_output(&path, false)?.write_all(serialized.as_bytes())?;
    }
    if updated == 0
        && let Some(want) = iface
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no config for iface {want} in {}", dir.display()),
        ));
    }
    Ok(updated)
}

/// Interface names are identifiers, never caller-supplied paths.
pub(crate) fn valid_iface(iface: &str) -> bool {
    (1..=15).contains(&iface.len()) && !iface.starts_with('-')
        && iface.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn invalid_iface(error: impl std::fmt::Display) -> serde_json::Value {
    // The daemon uses line-delimited JSON over TCP, not HTTP.
    serde_json::json!({ "status": 400, "error": error.to_string() })
}

/// Resolve a direct child of the configuration directory. Reject symlinks
/// (including dangling ones) before canonicalization or any file side effects.
fn confined_path(dir: &Path, iface: &str, extension: &str, optional: bool) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};
    if !valid_iface(iface) { return Err(Error::new(ErrorKind::InvalidInput, "invalid iface")); }
    confined_file(dir, std::ffi::OsStr::new(&format!("{iface}.{extension}")), optional)
}

fn confined_file(dir: &Path, name: &std::ffi::OsStr, optional: bool) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};
    let root = dir.canonicalize()?;
    let path = root.join(name);
    if path.parent() != Some(root.as_path()) {
        return Err(Error::new(ErrorKind::InvalidInput, "path escapes configuration directory"));
    }
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.file_type().is_file() {
                return Err(Error::new(ErrorKind::InvalidInput, "membership paths must be regular files"));
            }
            let resolved = path.canonicalize()?;
            if resolved.parent() != Some(root.as_path()) {
                return Err(Error::new(ErrorKind::InvalidInput, "path escapes configuration directory"));
            }
            Ok(resolved)
        }
        Err(e) if optional && e.kind() == ErrorKind::NotFound => Ok(path),
        Err(e) => Err(e),
    }
}

fn member_config(dir: &Path, iface: &str) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};
    if !valid_iface(iface) { return Err(Error::new(ErrorKind::InvalidInput, "invalid iface")); }
    // Membership is the on-disk config, even while its child is disconnected.
    // Keep supporting CLI configs with custom filenames (for example node.json).
    let mut members = configs(dir).into_iter().filter(|path| read_iface(path).as_deref() == Some(iface));
    let path = members.next().ok_or_else(|| Error::new(ErrorKind::InvalidInput, "iface is not a registered member"))?;
    if members.next().is_some() {
        return Err(Error::new(ErrorKind::InvalidInput, "iface has multiple membership configs"));
    }
    Ok(path)
}

/// Open the checked leaf without following a replacement symlink. Delay
/// truncation until the opened descriptor is verified to be a regular file.
fn open_output(path: &Path, create_new: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(!create_new).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() { return Err(std::io::Error::other("output is not a regular file")); }
    if !create_new { file.set_len(0)?; }
    Ok(file)
}

fn write_json(path: &Path, cfg: &serde_json::Value, create_new: bool) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(cfg).map_err(std::io::Error::other)?;
    let mut file = open_output(path, create_new)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")
}

/// Reserve a confined writable config slot before consuming an invitation.
/// The temporary-path guard removes the empty reservation on enrollment failure.
struct MemberSlot {
    file: tempfile::NamedTempFile,
    tun: String,
    port: u16,
}

impl MemberSlot {
    fn save(mut self, cfg: &serde_json::Value) -> std::io::Result<(PathBuf, String)> {
        let mut cfg = cfg.clone();
        let obj = cfg.as_object_mut().ok_or_else(|| std::io::Error::other("config must be an object"))?;
        obj.insert("tun_name".into(), self.tun.clone().into());
        obj.insert("listen_port".into(), self.port.into());
        let bytes = serde_json::to_vec_pretty(&cfg).map_err(std::io::Error::other)?;
        self.file.write_all(&bytes)?;
        self.file.write_all(b"\n")?;
        let (_, path) = self.file.keep().map_err(|error| error.error)?;
        Ok((path, self.tun))
    }
}

/// Join/import share an exclusive allocator. Occupied or unsafe config/log
/// slots are skipped; open/create_new both checks writability and reserves it.
fn reserve_member(dir: &Path) -> std::io::Result<MemberSlot> {
    let root = dir.canonicalize()?;
    let used: std::collections::HashSet<_> = configs(&root).iter().filter_map(|path| read_iface(path)).collect();
    for n in 0..=u16::MAX - 41820 {
        let tun = format!("fp{n}");
        if used.contains(&tun) { continue; }
        let candidate = root.join(format!("{tun}.json"));
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e),
        }
        match std::fs::symlink_metadata(root.join(format!("{tun}.log"))) {
            Ok(meta) if !meta.file_type().is_file() => continue,
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e),
        }
        let path = confined_path(&root, &tun, "json", true)?;
        confined_path(&root, &tun, "log", true)?;
        match open_output(&path, true) {
            Ok(file) => {
                let path = tempfile::TempPath::try_from_path(path)?;
                return Ok(MemberSlot { file: tempfile::NamedTempFile::from_parts(file, path), tun, port: 41820 + n });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free membership slot"))
}

impl Daemon {
    fn new(dir: PathBuf, token: String) -> Self {
        #[cfg(target_os = "macos")]
        let pf_base = if cfg!(test) { dir.join("pf") } else { PathBuf::from(crate::firewall::pf::BASE) };
        Self { #[cfg(test)] remove_link: None, #[cfg(target_os = "macos")] pf_base, dir, token, processes: Processes::default(), admission: tokio::sync::Mutex::new(()), guard_root: PathBuf::from(crate::carriers::ROOT), protected_members: parking_lot::Mutex::default(), exit: tokio::sync::Notify::new() }
    }

    // Cover validation, config writes, stop/restart and spawn registration with
    // one admission reservation: a second iface must not pass before a newly
    // started protected member has written its firewall journal.
    fn admission(&self) -> std::io::Result<tokio::sync::MutexGuard<'_, ()>> {
        self.admission.try_lock().map_err(|_| std::io::Error::new(std::io::ErrorKind::WouldBlock, "network admission busy; retry"))
    }

    fn check_member(&self, iface: &str, cfg: &serde_json::Value) -> std::io::Result<()> {
        crate::firewall::client::ensure_exclusive_at(&self.guard_root, iface)?;
        for other in self.processes.ifaces().into_iter().filter(|other| other != iface) {
            if cfg["kill_switch"] == true { return Err(other_membership_up(&other)); }
            let path = member_config(&self.dir, &other)?;
            let config: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?).map_err(std::io::Error::other)?;
            if self.protected_members.lock().contains(&other) || crate::firewall::client::requested(config["kill_switch"] == true, config["use_exit"].as_str()) {
                return Err(crate::firewall::client::exclusive_error(&other));
            }
        }
        Ok(())
    }

    /// Spawn a node task for one config (idempotent per interface).
    fn spawn_net(&self, cfg: &Path) -> std::io::Result<()> {
        let iface = read_iface(cfg).ok_or_else(|| std::io::Error::other("invalid membership config"))?;
        let _operation = self.processes.operation(&iface)?;
        let _admission = self.admission()?;
        self.spawn_net_locked(cfg, &iface)
    }

    fn spawn_net_locked(&self, cfg: &Path, iface: &str) -> std::io::Result<()> {
        let registered = member_config(&self.dir, iface)?;
        if cfg.canonicalize()? != registered { return Err(std::io::Error::other("unregistered config path")); }
        let config: serde_json::Value = serde_json::from_slice(&std::fs::read(&registered)?).map_err(std::io::Error::other)?;
        self.check_member(iface, &config)?;
        crate::firewall::client::validate_config(&config)?;
        if self.processes.running(iface)? { return Ok(()); }
        let exe = std::env::current_exe()?;
        let log_path = confined_path(&self.dir, iface, "log", true)?;
        let log = open_output(&log_path, false)?;
        let err = log.try_clone()?;
        let mut cmd = Command::new(exe);
        cmd.arg("node").arg("run").arg(&registered).stdout(log).stderr(err).kill_on_drop(true);
        if std::env::var_os("RUST_LOG").is_none() { cmd.env("RUST_LOG", "info"); }
        self.processes.spawn(iface, &mut cmd)?;
        let mut protected = self.protected_members.lock();
        if crate::firewall::client::requested(config["kill_switch"] == true, config["use_exit"].as_str()) { protected.insert(iface.to_string()); }
        else { protected.remove(iface); }
        Ok(())
    }

    /// Wait for the owning supervisor to reap the child before removing leftovers.
    /// Callers hold an interface operation or the global shutdown reservation.
    async fn stop_iface(&self, iface: &str) -> std::io::Result<()> {
        self.stop_iface_with_policy(iface, true).await
    }

    async fn stop_iface_with_policy(&self, iface: &str, release: bool) -> std::io::Result<()> {
        let stopped = self.processes.stop(iface).await;
        // stop() has reaped the member even if it reports failed host cleanup.
        // Only explicit down/disable releases OUTPUT, never a restart or crash.
        if release && !self.processes.contains(iface) {
            let iface = iface.to_string();
            crate::apply::blocking(move || crate::firewall::client::clear(&iface)).await?;
        }
        #[cfg(target_os = "macos")]
        if !self.processes.contains(iface) {
            let iface = iface.to_string(); let base = self.pf_base.clone();
            crate::apply::blocking(move || crate::firewall::pf::down_at(&base, &iface)).await?;
        }
        #[cfg(windows)]
        if !self.processes.contains(iface) {
            let iface = iface.to_string();
            crate::apply::blocking(move || crate::route::windows::recover(&iface).map_err(crate::apply::ApplyError::from)).await?;
        }
        if let Err(error) = std::fs::remove_file(crate::statusd::socket_path(iface))
            && error.kind() != std::io::ErrorKind::NotFound { return Err(error); }
        #[cfg(all(test, not(target_os = "linux")))]
        if let Some(remove) = self.remove_link {
            cleanup_link_with(iface.to_string(), remove).await.map_err(std::io::Error::other)?;
        }
        #[cfg(target_os = "linux")]
        {
            let remove: fn(String) -> crate::apply::Result = |iface| crate::apply::run(&["ip", "link", "del", "dev", &iface]);
            #[cfg(test)]
            let remove = self.remove_link.unwrap_or(remove);
            cleanup_link_with(iface.to_string(), remove).await.map_err(std::io::Error::other)?;
        }
        stopped?;
        self.processes.cleaned(iface);
        Ok(())
    }

    /// Stop all members with new lifecycle operations excluded. Only a successful
    /// teardown authorizes handle() to end the accept loop after flushing its ack.
    async fn shutdown(&self) -> serde_json::Value {
        let reservation = match self.processes.quiesce() {
            Ok(reservation) => reservation, Err(error) => return lifecycle_error(error),
        };
        let mut errors = Vec::new();
        let mut ifaces = self.processes.cleanup_ifaces();
        ifaces.extend(configs(&self.dir).iter().filter_map(|path| read_iface(path)));
        ifaces.sort(); ifaces.dedup();
        for iface in ifaces {
            if let Err(error) = self.stop_iface(&iface).await { errors.push(format!("{iface}: {error}")); }
        }
        if !errors.is_empty() { return serde_json::json!({"error":errors.join("; ")}); }
        reservation.commit();
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
        let sent = async {
            s.write_all(serde_json::to_string(&resp).unwrap_or_default().as_bytes()).await?;
            s.write_all(b"\n").await?;
            s.flush().await
        }.await;
        if resp["shutdown"] == true && resp["ok"] == true { self.exit.notify_one(); }
        sent
    }

    async fn dispatch(&self, req: &serde_json::Value) -> serde_json::Value {
        let cmd = req["cmd"].as_str().unwrap_or("");
        if matches!(cmd, "up" | "down" | "settings" | "config" | "get_config" | "set-config" | "set_config" | "leave" | "logs")
            && let Err(error) = self.validate_operation(req["iface"].as_str().unwrap_or(""), matches!(cmd, "down" | "leave"))
        {
            return invalid_iface(error);
        }
        match cmd {
            // Live status of every running network (for the GUI dashboard).
            "status" => self.annotate_status(crate::show::aggregate_status().await),
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
            "shutdown" => self.shutdown().await,
            // Tail a network's node log (for the GUI diagnostics panel).
            "logs" => self.logs(
                req["iface"].as_str().unwrap_or(""),
                req["lines"].as_u64().unwrap_or(200) as usize,
            ),
            other => serde_json::json!({ "error": format!("unknown cmd: {other}") }),
        }
    }

    fn validate_operation(&self, iface: &str, stopping: bool) -> std::io::Result<()> {
        if !valid_iface(iface) { return Err(std::io::Error::other("invalid iface")); }
        if stopping && (self.processes.contains(iface) || self.processes.needs_cleanup(iface)) { return Ok(()); }
        member_config(&self.dir, iface).map(|_| ())
    }

    fn duplicate_ifaces(&self) -> Vec<String> {
        let mut counts = HashMap::<String, usize>::new();
        for path in configs(&self.dir) {
            if let Some(iface) = read_iface(&path) { *counts.entry(iface).or_default() += 1; }
        }
        let mut duplicates: Vec<_> = counts.into_iter().filter_map(|(iface, n)| (n > 1).then_some(iface)).collect();
        duplicates.sort(); duplicates
    }

    fn annotate_status(&self, mut status: serde_json::Value) -> serde_json::Value {
        if let Some(entries) = status.as_array_mut() {
            for iface in self.duplicate_ifaces() {
                entries.push(serde_json::json!({"iface":iface, "membership_error":"multiple membership configs",
                    "up":self.processes.contains(&iface)}));
            }
        }
        status
    }

    fn networks(&self) -> serde_json::Value {
        let duplicates = self.duplicate_ifaces();
        let mut arr = Vec::new();
        for cfg in configs(&self.dir) {
            if let Ok(s) = std::fs::read_to_string(&cfg)
                && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
            {
                let iface = v["tun_name"].as_str().unwrap_or("?").to_string();
                let (up, exited) = self.processes.snapshot(&iface);
                let last_error = crate::statusd::read_failure(&crate::statusd::socket_path(&iface))
                    .and_then(|v| v["interface"]["last_error"].as_str().map(String::from))
                    .or_else(|| exited.as_ref().and_then(|info| info.last_error.clone()));
                arr.push(serde_json::json!({
                    "iface": iface,
                    "membership_error": if duplicates.contains(&iface) { Some("multiple membership configs") } else { None },
                    "control_server": v["control_server"].as_str().unwrap_or(""),
                    "up": up,
                    "last_exit_code": exited.as_ref().and_then(|info| info.code),
                    "forced_termination": exited.as_ref().is_some_and(|info| info.forced),
                    "last_error": last_error,
                    "exit_node": v["exit_node"].as_bool().unwrap_or(false),
                    "exit_veto": v["exit_veto"].as_bool().unwrap_or(false),
                    "firewall_trust_external": v["firewall_trust_external"].as_bool().unwrap_or(false),
                    // Consumer exit selection (AD-2); absent = split-tunnel.
                    "use_exit": v["use_exit"].as_str().unwrap_or("off"),
                    "kill_switch": v["kill_switch"].as_bool().unwrap_or(false),
                    "force_relay": v["force_relay"].as_bool().unwrap_or(false),
                    "relay_anytls": v["relay_anytls"].as_bool().unwrap_or(false),
                    "relay_bond": v["relay_bond"].as_bool().unwrap_or(false),
                }));
            }
        }
        serde_json::Value::Array(arr)
    }

    async fn join(&self, token: &str) -> serde_json::Value {
        self.join_with(token, |path| self.spawn_net(path)).await
    }

    async fn join_with(&self, token: &str, spawn: impl FnOnce(&Path) -> std::io::Result<()>) -> serde_json::Value {
        let slot = match reserve_member(&self.dir) {
            Ok(slot) => slot,
            Err(error) => return serde_json::json!({"error":format!("membership save failed (preflight): {error}")}),
        };
        match crate::join::enroll_config(token, None).await {
            Ok(cfg) => Self::start_member(slot.save(&cfg), spawn),
            Err(error) => serde_json::json!({"error":error.to_string()}),
        }
    }

    fn install_member(&self, cfg: &serde_json::Value, spawn: impl FnOnce(&Path) -> std::io::Result<()>) -> serde_json::Value {
        if let Err(error) = crate::firewall::client::validate_config(cfg) { return invalid_iface(error); }
        Self::start_member(reserve_member(&self.dir).and_then(|slot| slot.save(cfg)), spawn)
    }

    fn start_member(saved: std::io::Result<(PathBuf, String)>, spawn: impl FnOnce(&Path) -> std::io::Result<()>) -> serde_json::Value {
        match saved {
            Ok((path, iface)) => match spawn(&path) {
                Ok(()) => serde_json::json!({"ok":true, "iface":iface}),
                Err(error) => {
                    let message = format!("membership saved but start failed: {error}");
                    let mut response = lifecycle_error(error); response["error"] = message.into(); response["iface"] = iface.into(); response
                },
            },
            Err(error) => serde_json::json!({"error":format!("membership save failed: {error}")}),
        }
    }

    /// Return a network config JSON with the private key redacted. The local
    /// daemon token is enough to operate networks, but must not disclose key
    /// material to API clients.
    fn get_config(&self, iface: &str) -> serde_json::Value {
        let path = match member_config(&self.dir, iface) {
            Ok(path) => path, Err(error) => return invalid_iface(error),
        };
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
        let _operation = match self.processes.operation(iface) {
            Ok(operation) => operation, Err(error) => return lifecycle_error(error),
        };
        let _admission = match self.admission() {
            Ok(admission) => admission, Err(error) => return lifecycle_error(error),
        };
        let path = match self.store_config(req) {
            Ok(path) => path, Err(error) => return config_error(error),
        };
        if let Err(error) = self.restart(iface, &path).await { return lifecycle_error(error); }
        serde_json::json!({ "ok": true, "iface": iface })
    }

    fn store_config(&self, req: &serde_json::Value) -> std::io::Result<PathBuf> {
        use std::io::{Error, ErrorKind};
        let iface = req["iface"].as_str().unwrap_or("");
        let path = member_config(&self.dir, iface)?;
        let mut cfg = req["config"].clone();
        let obj = cfg.as_object_mut().ok_or_else(|| Error::new(ErrorKind::InvalidInput, "config must be an object"))?;
        if obj.get("tun_name").and_then(|v| v.as_str()) != Some(iface) {
            return Err(Error::new(ErrorKind::InvalidInput, "config tun_name must match the registered iface"));
        }
        let preserve = match obj.get("private_key") {
            None => true,
            Some(serde_json::Value::String(key)) if key == "<redacted>" => true,
            Some(serde_json::Value::String(key)) if !key.is_empty() => false,
            _ => return Err(Error::new(ErrorKind::InvalidInput, "private_key must be a nonempty string or omitted")),
        };
        if preserve {
            let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "cannot read existing config"))?;
            let key = original.get("private_key").and_then(|v| v.as_str())
                .filter(|key| !key.is_empty() && *key != "<redacted>")
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "existing private key is unavailable"))?;
            obj.insert("private_key".into(), serde_json::Value::String(key.to_string()));
        }
        self.check_member(iface, &cfg)?;
        crate::firewall::client::validate_config(&cfg)?;
        write_json(&path, &cfg, false)?;
        Ok(path)
    }

    /// Import a network config (from a file the GUI read) as a new network + up it.
    async fn import(&self, req: &serde_json::Value) -> serde_json::Value {
        self.import_with(req, |path| self.spawn_net(path))
    }

    fn import_with(&self, req: &serde_json::Value, spawn: impl FnOnce(&Path) -> std::io::Result<()>) -> serde_json::Value {
        let cfg = &req["config"];
        if !cfg.is_object() || cfg["private_key"].as_str().is_none() {
            return serde_json::json!({ "error": "not a fluxpeer node config (need private_key, device_id, control_server)" });
        }
        self.install_member(cfg, spawn)
    }

    /// Leave a network permanently: stop it, then delete its on-disk config + log
    /// so it no longer appears in `networks` and won't auto-start next daemon run.
    /// (Control-server membership is left intact — re-joining just needs the token.)
    async fn leave(&self, iface: &str) -> serde_json::Value {
        if let Err(error) = self.validate_operation(iface, true) { return invalid_iface(error); }
        let _operation = match self.processes.operation(iface) {
            Ok(operation) => operation, Err(error) => return lifecycle_error(error),
        };
        let cfg = member_config(&self.dir, iface);
        if let Err(error) = self.stop_iface(iface).await { return lifecycle_error(error); }
        let cfg = match cfg {
            Ok(path) => path,
            Err(_) => return serde_json::json!({"iface":iface, "up":false, "left":false,
                "error":"stopped; membership cleanup requires a unique valid config"}),
        };
        if let Err(error) = std::fs::remove_file(cfg) { return serde_json::json!({"error":error.to_string(), "up":false}); }
        let log = match confined_path(&self.dir, iface, "log", true) {
            Ok(path) => path,
            Err(error) => return serde_json::json!({"error":error.to_string(), "up":false}),
        };
        if let Err(error) = std::fs::remove_file(log)
            && error.kind() != std::io::ErrorKind::NotFound
        { return serde_json::json!({"error":error.to_string(), "up":false}); }
        serde_json::json!({ "ok": true, "iface": iface, "left": true })
    }

    /// Return the last `lines` of a network's node log (diagnostics panel).
    fn logs(&self, iface: &str, lines: usize) -> serde_json::Value {
        if let Err(error) = member_config(&self.dir, iface) { return invalid_iface(error); }
        let path = match confined_path(&self.dir, iface, "log", true) {
            Ok(path) => path, Err(error) => return invalid_iface(error),
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return serde_json::json!({ "iface": iface, "log": "" });
        };
        let n = lines.clamp(1, 2000);
        let tail: Vec<&str> = raw.lines().rev().take(n).collect();
        let joined: String = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
        serde_json::json!({ "iface": iface, "log": strip_ansi(&joined) })
    }

    /// Restart one network (down + up) to apply a config change.
    async fn restart(&self, iface: &str, path: &Path) -> std::io::Result<()> {
        let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?).map_err(std::io::Error::other)?;
        let active = crate::firewall::client::validate_config(&cfg)?;
        self.stop_iface_with_policy(iface, !active).await?;
        self.spawn_net_locked(path, iface)
    }

    /// Edit a network's own wg settings in its local config + restart it to apply.
    async fn settings(&self, req: &serde_json::Value) -> serde_json::Value {
        let iface = req["iface"].as_str().unwrap_or("");
        let _operation = match self.processes.operation(iface) {
            Ok(operation) => operation, Err(error) => return lifecycle_error(error),
        };
        let _admission = match self.admission() {
            Ok(admission) => admission, Err(error) => return lifecycle_error(error),
        };
        let path = match member_config(&self.dir, iface) {
            Ok(path) => path, Err(error) => return invalid_iface(error),
        };
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
        if let Err(error) = apply_firewall_setting(&mut cfg, req) {
            return serde_json::json!({ "error": error });
        }
        // Local force-on follows AD-1; cancellation returns to control approval.
        if let Some(obj) = cfg.as_object_mut() { apply_provider_settings(obj, req); }
        // Use an EXIT PEER for this device's own traffic (AD-2): `auto`/`off`/
        // `<pubkey hex>`; `off` removes the key (split is the default).
        if let Some(value) = req.get("use_exit") {
            let Some(ue) = value.as_str() else {
                return serde_json::json!({ "error": "use_exit must be a string" });
            };
            match normalize_use_exit(ue) {
                Ok(mode) => {
                    if let Some(obj) = cfg.as_object_mut() {
                        if mode == "off" {
                            obj.remove("use_exit");
                        } else {
                            obj.insert("use_exit".to_string(), serde_json::json!(mode));
                        }
                    }
                }
                Err(e) => return serde_json::json!({ "error": e }),
            }
        }
        // Connection mode (transport policy): force-relay + relay flavor.
        if let Some(value) = req.get("kill_switch") { cfg["kill_switch"] = value.clone(); }
        if let Err(error) = self.check_member(iface, &cfg) { return lifecycle_error(error); }
        if let Err(error) = crate::firewall::client::validate_config(&cfg) {
            return serde_json::json!({"error": error.to_string()});
        }
        for k in ["force_relay", "relay_anytls", "relay_bond"] {
            if let Some(b) = req.get(k).and_then(|x| x.as_bool()) {
                cfg[k] = serde_json::json!(b);
            }
        }
        if write_json(&path, &cfg, false).is_err() {
            return serde_json::json!({ "error": "write failed" });
        }
        if let Err(error) = self.restart(iface, &path).await { return lifecycle_error(error); } // MTU/DNS/endpoint take effect on restart
        serde_json::json!({ "ok": true, "iface": iface })
    }

    /// Connect (`up=true`) or disconnect (`up=false`) one network.
    async fn set_iface(&self, iface: &str, up: bool) -> serde_json::Value {
        if let Err(error) = self.validate_operation(iface, !up) { return invalid_iface(error); }
        let _operation = match self.processes.operation(iface) {
            Ok(operation) => operation, Err(error) => return lifecycle_error(error),
        };
        let _admission = match self.admission() {
            Ok(admission) => admission, Err(error) => return lifecycle_error(error),
        };
        if up {
            let cfg = match member_config(&self.dir, iface) { Ok(path) => path, Err(error) => return invalid_iface(error) };
            if let Err(error) = self.spawn_net_locked(&cfg, iface) { return lifecycle_error(error); }
        } else {
            if let Err(error) = self.stop_iface(iface).await { return lifecycle_error(error); }
        }
        serde_json::json!({ "ok": true, "iface": iface, "up": self.processes.contains(iface) })
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
            if p.extension().is_some_and(|x| x == "json")
                && let Some(name) = p.file_name()
                && let Ok(path) = confined_file(dir, name, false)
                && let Some(iface) = read_iface(&path)
                && valid_iface(&iface)
                && confined_path(dir, &iface, "log", true).is_ok()
            {
                out.push(path);
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
    ensure_token_with_rng(dir, getrandom::getrandom)
}

fn ensure_token_with_rng(dir: &Path, fill: impl FnOnce(&mut [u8]) -> Result<(), getrandom::Error>) -> std::io::Result<String> {
    let path = dir.join("daemon.token");
    if let Ok(t) = std::fs::read_to_string(&path)
        && t.trim().len() >= 16
    {
        return Ok(t.trim().to_string());
    }
    // CSPRNG bearer token, cross-platform via getrandom (no /dev/urandom, which
    // is absent on Windows; the old time/pid fallback was guessable).
    let mut buf = [0u8; 24];
    fill(&mut buf).map_err(|error| std::io::Error::other(format!("OS CSPRNG failed: {error}")))?;
    let token: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&path, &token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_rng_failure_does_not_create_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let result = ensure_token_with_rng(dir.path(), |_| Err(getrandom::Error::UNSUPPORTED));
        assert!(result.unwrap_err().to_string().contains("OS CSPRNG failed"));
        assert!(!dir.path().join("daemon.token").exists());
    }

    /// A fresh temp config dir with one minimal membership config per iface.
    struct TempDir { path: PathBuf, _owner: tempfile::TempDir }
    impl TempDir {
        fn new(ifaces: &[&str]) -> Self {
            let owner = tempfile::tempdir().expect("mk tempdir");
            let dir = owner.path().to_path_buf();
            for (i, iface) in ifaces.iter().enumerate() {
                let cfg = serde_json::json!({
                    "private_key": "00", "device_id": format!("d{i}"),
                    "control_server": "http://127.0.0.1:8080",
                    "listen_port": 51820 + i as u16, "tun_name": iface, "prefix_len": 24,
                });
                std::fs::write(dir.join(format!("{iface}.json")), cfg.to_string()).expect("write cfg");
            }
            TempDir { path: dir, _owner: owner }
        }
        fn read(&self, iface: &str) -> serde_json::Value {
            let s = std::fs::read_to_string(self.path.join(format!("{iface}.json"))).expect("read cfg");
            serde_json::from_str(&s).expect("cfg json")
        }
    }

    #[test]
    fn concurrent_daemon_fixtures_are_isolated_and_owned_until_drop() {
        let fixtures: Vec<_> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..32).map(|_| scope.spawn(|| TempDir::new(&["fp0"]))).collect();
            workers.into_iter().map(|worker| worker.join().unwrap()).collect()
        });
        let paths: std::collections::HashSet<_> = fixtures.iter().map(|fixture| fixture.path.clone()).collect();
        assert_eq!(paths.len(), fixtures.len());
        for fixture in &fixtures { assert_eq!(fixture.read("fp0")["device_id"], "d0"); }
        drop(fixtures);
        assert!(paths.iter().all(|path| !path.exists()));
    }

    #[test]
    fn kill_switch_cli_defaults_false_and_scopes_local_configuration() {
        let temp = TempDir::new(&["fp0", "fp1"]);
        let dir = temp.path.to_str().unwrap();
        let config: crate::Config = serde_json::from_value(temp.read("fp0")).unwrap();
        assert!(!config.kill_switch);
        assert_eq!(set_kill_switch(dir, Some("fp0"), true).unwrap(), 1);
        assert_eq!(temp.read("fp0")["kill_switch"], true);
        assert!(temp.read("fp1").get("kill_switch").is_none());
        assert!(temp.read("fp0").get("use_exit").is_none());
        assert_eq!(set_kill_switch(dir, Some("fp0"), false).unwrap(), 1);
        assert_eq!(temp.read("fp0")["kill_switch"], false);
        assert!(set_kill_switch(dir, Some("fp9"), true).is_err());
    }

    #[tokio::test]
    async fn invalid_or_unsupported_guard_settings_leave_config_and_processes_unchanged() {
        let temp = TempDir::new(&["fp0"]);
        let daemon = Daemon::new(temp.path.clone(), String::new());
        let original = temp.read("fp0");
        let mut values = vec![serde_json::json!({"iface":"fp0", "kill_switch":"true"}),
            serde_json::json!({"iface":"fp0", "kill_switch":null})];
        if !cfg!(target_os = "linux") { values.push(serde_json::json!({"iface":"fp0", "kill_switch":true, "use_exit":"auto"})); }
        for request in values {
            assert!(daemon.settings(&request).await.get("error").is_some());
            assert_eq!(temp.read("fp0"), original);
            assert!(daemon.processes.ifaces().is_empty());
        }
        let mut invalid = original.clone(); invalid["kill_switch"] = serde_json::json!(1);
        assert!(serde_json::from_value::<crate::Config>(invalid.clone()).is_err());
        assert!(daemon.store_config(&serde_json::json!({"iface":"fp0", "config":invalid})).is_err());
        assert_eq!(temp.read("fp0"), original);
    }

    #[tokio::test]
    async fn daemon_rejects_invalid_use_exit_without_writing_or_starting_a_node() {
        let temp = TempDir::new(&["fp0"]);
        let daemon = Daemon::new(temp.path.clone(), String::new());
        let original = temp.read("fp0");
        for mode in [serde_json::json!(true), serde_json::json!("bad-key")] {
            let result = daemon.settings(&serde_json::json!({"iface": "fp0", "use_exit": mode})).await;
            assert!(result.get("error").is_some());
            assert_eq!(temp.read("fp0"), original);
            assert!(daemon.processes.ifaces().is_empty());
        }
    }

    #[tokio::test]
    async fn daemon_rejects_non_boolean_firewall_trust_without_writing_or_restart() {
        let temp = TempDir::new(&["fp0"]);
        let daemon = Daemon::new(temp.path.clone(), String::new());
        let original = temp.read("fp0");
        for value in [serde_json::json!("true"), serde_json::json!(1), serde_json::Value::Null] {
            let result = daemon.settings(&serde_json::json!({"iface":"fp0", "firewall_trust_external":value})).await;
            assert!(result.get("error").is_some()); assert_eq!(temp.read("fp0"), original);
            assert!(daemon.processes.ifaces().is_empty());
        }
    }

    #[test]
    fn firewall_settings_round_trip_and_reject_invalid_types() {
        let mut cfg = serde_json::json!({});
        apply_firewall_setting(&mut cfg, &serde_json::json!({})).unwrap();
        assert!(cfg.get("firewall_trust_external").is_none());
        for enabled in [true, false] {
            apply_firewall_setting(&mut cfg, &serde_json::json!({"firewall_trust_external":enabled})).unwrap();
            assert_eq!(cfg["firewall_trust_external"], enabled);
        }
        for value in [serde_json::json!("true"), serde_json::json!(1), serde_json::Value::Null] {
            assert!(apply_firewall_setting(&mut cfg, &serde_json::json!({"firewall_trust_external":value})).is_err());
            assert_eq!(cfg["firewall_trust_external"], false);
        }
    }

    #[test]
    fn normalize_use_exit_accepts_off_auto_hex() {
        assert_eq!(normalize_use_exit("off").as_deref(), Ok("off"));
        assert_eq!(normalize_use_exit("").as_deref(), Ok("off"));
        assert_eq!(normalize_use_exit("auto").as_deref(), Ok("auto"));
        let upper = "AB".repeat(32);
        assert_eq!(normalize_use_exit(&upper).as_deref(), Ok(upper.to_ascii_lowercase().as_str()));
        assert!(normalize_use_exit("xyz").is_err());
        assert!(normalize_use_exit(&"ab".repeat(31)).is_err()); // 62 chars
    }

    #[test]
    fn daemon_provider_settings_off_follows_approval_and_veto_is_explicit() {
        let mut cfg = serde_json::json!({"exit_node":true});
        apply_provider_settings(cfg.as_object_mut().unwrap(), &serde_json::json!({"exit_node":false}));
        assert_eq!(cfg, serde_json::json!({}));
        apply_provider_settings(cfg.as_object_mut().unwrap(), &serde_json::json!({"exit_veto":true}));
        assert_eq!(cfg, serde_json::json!({"exit_veto":true}));
        apply_provider_settings(cfg.as_object_mut().unwrap(), &serde_json::json!({"exit_node":false}));
        assert_eq!(cfg, serde_json::json!({}));
        apply_provider_settings(cfg.as_object_mut().unwrap(), &serde_json::json!({"exit_node":true, "exit_veto":true}));
        assert_eq!(cfg, serde_json::json!({"exit_node":true, "exit_veto":true}));
        apply_provider_settings(cfg.as_object_mut().unwrap(), &serde_json::json!({"exit_veto":false}));
        assert_eq!(cfg, serde_json::json!({"exit_node":true}));
    }

    #[test]
    fn set_exit_off_follows_control_and_explicit_veto_is_separate() {
        let t = TempDir::new(&["fp0"]);
        let dir = t.path.to_string_lossy().to_string();
        assert_eq!(set_exit(&dir, true).expect("on"), 1);
        let cfg = t.read("fp0");
        assert_eq!(cfg["exit_node"], true);
        assert!(cfg.get("exit_veto").is_none());

        assert_eq!(set_exit(&dir, false).expect("off"), 1);
        let cfg = t.read("fp0");
        assert!(cfg.get("exit_node").is_none(), "off removes the key (AD-1)");
        assert!(cfg.get("exit_veto").is_none());
        assert_eq!(veto_exit(&dir).expect("veto"), 1);
        assert_eq!(t.read("fp0")["exit_veto"], true);
        assert_eq!(set_exit(&dir, false).expect("follow"), 1);
        assert!(t.read("fp0").get("exit_veto").is_none());
    }

    #[test]
    fn set_use_exit_scopes_by_iface_and_off_removes_key() {
        let t = TempDir::new(&["fp0", "fp1"]);
        let dir = t.path.to_string_lossy().to_string();
        // One iface only.
        assert_eq!(set_use_exit(&dir, Some("fp0"), "auto").expect("auto"), 1);
        assert_eq!(t.read("fp0")["use_exit"], "auto");
        assert!(t.read("fp1").get("use_exit").is_none());
        // All ifaces when no filter.
        let pk = "cd".repeat(32);
        assert_eq!(set_use_exit(&dir, None, &pk).expect("pin"), 2);
        assert_eq!(t.read("fp1")["use_exit"], serde_json::json!(pk));
        // off removes the key.
        assert_eq!(set_use_exit(&dir, Some("fp0"), "off").expect("off"), 1);
        assert!(t.read("fp0").get("use_exit").is_none());
        // Invalid mode is an error, nothing written.
        assert!(set_use_exit(&dir, None, "bogus").is_err());
        // Unknown iface is an error.
        assert!(set_use_exit(&dir, Some("fp9"), "auto").is_err());
    }
}

#[cfg(test)]
#[path = "daemon_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "daemon_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "daemon_killswitch_tests.rs"]
mod killswitch_tests;
