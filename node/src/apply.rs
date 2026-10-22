// SPDX-License-Identifier: BSD-3-Clause
//! Checked host effects and structured errors shared by routing, DNS and NAT.

use std::io::{self, Read, Seek, Write};
use std::time::{Duration, Instant};
use std::process::{Command, Stdio};

pub(crate) type Result<T = ()> = std::result::Result<T, ApplyError>;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ApplyError {
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub stderr: String,
    #[serde(skip)]
    pub kind: io::ErrorKind,
}

impl ApplyError {
    pub fn new(command: &[&str], stderr: impl Into<String>) -> Self {
        Self { command: command.iter().map(|s| s.to_string()).collect(), exit_code: None, stderr: stderr.into(), kind: io::ErrorKind::Other }
    }
    pub fn io(command: &[&str], error: io::Error) -> Self {
        Self { kind: error.kind(), ..Self::new(command, error.to_string()) }
    }
    pub fn missing(&self) -> bool {
        self.stderr.contains("No such process") || self.stderr.contains("No such file or directory")
            || self.stderr.contains("not in table") || self.stderr.contains("does not exist")
    }
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (exit {:?}): {}", self.command.join(" "), self.exit_code, self.stderr.trim())
    }
}
impl std::error::Error for ApplyError {}
impl From<ApplyError> for io::Error {
    fn from(error: ApplyError) -> Self { io::Error::new(error.kind, error) }
}

impl From<io::Error> for ApplyError {
    fn from(error: io::Error) -> Self {
        if let Some(original) = error.get_ref().and_then(|e| e.downcast_ref::<ApplyError>()) { return original.clone(); }
        Self::io(&["host effect"], error)
    }
}

pub(crate) trait Runner {
    fn run(&mut self, command: &[&str], input: Option<&str>) -> Result<String>;
    /// Persist stdout and stderr directly, including output from a child that
    /// outlives a crashed caller. PF enable tokens are emitted on stderr.
    #[cfg(any(target_os = "macos", test))]
    fn run_recorded(&mut self, command: &[&str], receipt: &std::path::Path) -> Result<String> {
        let output = self.run(command, None)?;
        use std::fs::OpenOptions;
        let mut options = OpenOptions::new(); options.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(receipt)?;
        file.write_all(output.as_bytes())?; file.sync_all()?;
        Ok(output)
    }
    fn write_file(&mut self, path: &std::path::Path, data: &[u8]) -> Result {
        write_file_with(path, data, has_selinux_label, |from, to| std::fs::rename(from, to))
            .map_err(|e| ApplyError::io(&["write", &path.to_string_lossy()], e))
    }
}
// Preserve security labels on the original inode. Absence/unsupported xattrs
// permit rename; other inspection failures must not silently discard labels.
fn has_selinux_label(file: &std::fs::File) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: the fd is live, the name is NUL-terminated; a null buffer with
        // size zero asks only for the attribute's length.
        let size = unsafe { libc::fgetxattr(file.as_raw_fd(), c"security.selinux".as_ptr(), std::ptr::null_mut(), 0) };
        if size >= 0 { return Ok(true); }
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) { Ok(false) } else { Err(error) }
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = file; Ok(false) }
}
fn write_file_with(
    path: &std::path::Path, data: &[u8],
    labeled: impl FnOnce(&std::fs::File) -> io::Result<bool>,
    rename: impl FnOnce(&std::path::Path, &std::path::Path) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::other("missing target directory"))?;
    let original = match std::fs::File::open(path) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let in_place = || -> io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
        file.write_all(data)?;
        file.sync_all()
    };
    if let Some(file) = &original && labeled(file)? { return in_place(); }
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    if let Some(file) = &original {
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
            // SAFETY: temp owns the live fd; uid/gid came from target metadata.
            if unsafe { libc::fchown(temp.as_file().as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // chown may clear mode bits, so apply permissions afterwards.
        temp.as_file().set_permissions(metadata.permissions())?;
    } else {
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; temp.as_file().set_permissions(std::fs::Permissions::from_mode(0o644))?; }
    }
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    match rename(temp.path(), path) {
        Ok(()) => {},
        Err(error) if matches!(error.kind(), io::ErrorKind::ResourceBusy | io::ErrorKind::CrossesDevices) => return in_place(),
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) struct System;
impl Runner for System {
    fn run(&mut self, command: &[&str], input: Option<&str>) -> Result<String> {
        run_timeout(command, input, Duration::from_secs(10))
    }
    #[cfg(any(target_os = "macos", test))]
    fn run_recorded(&mut self, command: &[&str], receipt: &std::path::Path) -> Result<String> {
        run_captured(command, None, Duration::from_secs(10), Some(receipt))
    }
}

fn run_timeout(command: &[&str], input: Option<&str>, timeout: Duration) -> Result<String> {
    run_captured(command, input, timeout, None)
}

fn run_captured(command: &[&str], input: Option<&str>, timeout: Duration, receipt: Option<&std::path::Path>) -> Result<String> {
    let execute = || -> io::Result<(std::process::ExitStatus, String, String, bool)> {
        let Some((program, args)) = command.split_first() else { return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command")); };
        // Temporary files avoid pipe deadlocks (including a child that never reads
        // stdin, or a descendant keeping stdout open after its parent exits).
        let mut stdout = if let Some(path) = receipt {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).read(true).create_new(true);
            #[cfg(unix)]
            { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
            let file = options.open(path)?;
            if let Some(parent) = path.parent() { std::fs::File::open(parent)?.sync_all()?; }
            file
        } else { tempfile::tempfile()? };
        let mut stderr = if receipt.is_some() { stdout.try_clone()? } else { tempfile::tempfile()? };
        let mut cmd = Command::new(program);
        cmd.args(args).env("LC_ALL", "C").stdout(stdout.try_clone()?).stderr(stderr.try_clone()?);
        #[cfg(unix)]
        { use std::os::unix::process::CommandExt; cmd.process_group(0); }
        #[cfg(windows)]
        { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }
        if let Some(input) = input {
            let mut stdin = tempfile::tempfile()?;
            stdin.write_all(input.as_bytes())?;
            stdin.rewind()?;
            cmd.stdin(stdin);
        } else { cmd.stdin(Stdio::null()); }
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                // No child ran: remove the pre-created receipt so recovery can
                // distinguish a failed spawn from an ambiguous interrupted one.
                if let Some(path) = receipt { std::fs::remove_file(path)?; }
                return Err(error);
            }
        };
        let deadline = Instant::now() + timeout;
        let (status, timed_out) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (status, false),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                result => {
                    #[cfg(unix)]
                    if let Ok(pid) = i32::try_from(child.id()) {
                        // SAFETY: this PID is our unreaped child's new process group;
                        // kill takes no pointers and cannot target our own group.
                        unsafe { libc::kill(-pid, libc::SIGKILL); }
                    }
                    if let Err(error) = child.kill() { tracing::debug!(%error, "child kill after timeout/poll error"); }
                    let status = child.wait()?;
                    result?;
                    break (status, true);
                }
            }
        };
        if receipt.is_some() { stdout.sync_all()?; }
        stdout.rewind()?;
        if receipt.is_none() { stderr.rewind()?; }
        let mut out = Vec::new();
        let mut err = Vec::new();
        stdout.read_to_end(&mut out)?;
        if receipt.is_none() { stderr.read_to_end(&mut err)?; } else { err.clone_from(&out); }
        Ok((status, String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned(), timed_out))
    };
    let (status, out, mut stderr, timed_out) = execute().map_err(|e| ApplyError::io(command, e))?;
    if timed_out { stderr.push_str(&format!("; command timeout after {} ms; killed and reaped", timeout.as_millis())); }
    if timed_out || !status.success() {
        return Err(ApplyError { command: command.iter().map(|s| s.to_string()).collect(), exit_code: status.code(), stderr,
            kind: if timed_out { io::ErrorKind::TimedOut } else { io::ErrorKind::Other } });
    }
    Ok(out)
}

pub(crate) fn run(command: &[&str]) -> Result { System.run(command, None).map(|_| ()) }
pub(crate) fn output(command: &[&str]) -> Result<String> { System.run(command, None) }
#[cfg(target_os = "macos")]
pub(crate) fn input(command: &[&str], data: &str) -> Result { System.run(command, Some(data)).map(|_| ()) }
pub(crate) fn write(path: &str, data: impl AsRef<[u8]>) -> Result {
    std::fs::write(path, data).map_err(|e| ApplyError::io(&["write", path], e))
}
pub(crate) fn remove(path: &str) -> Result {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ApplyError::io(&["remove", path], e)),
    }
}

/// Teardown must attempt every effect and retain the first failure for retry.
pub(crate) fn all(results: impl IntoIterator<Item = Result>) -> Result {
    let mut errors: Vec<_> = results.into_iter().filter_map(std::result::Result::err).collect();
    errors.sort_by(|a, b| (&a.command, a.exit_code, &a.stderr).cmp(&(&b.command, b.exit_code, &b.stderr)));
    errors.dedup();
    let mut errors = errors.into_iter();
    let Some(mut first) = errors.next() else { return Ok(()); };
    for error in errors { first.stderr.push_str(&format!("; additional effect: {error}")); }
    Err(first)
}

/// Only a fully applied snapshot advances the acknowledgement or clears errors.
#[derive(Default, serde::Serialize)]
pub(crate) struct Status {
    pub last_error: Option<ApplyError>,
    pub applied_epoch: Option<u64>,
    pub restart_required: bool,
}
pub(crate) type SharedStatus = std::sync::Arc<parking_lot::Mutex<Status>>;
enum ApplyEvent<'a> { Failed(&'a ApplyError), Recovered }
impl Status {
    pub fn complete(&mut self, epoch: u64, result: Result) {
        self.complete_with(epoch, result, |event| match event {
            ApplyEvent::Failed(error) => tracing::error!(%error, epoch, "configuration apply failed; retrying with backoff"),
            ApplyEvent::Recovered => tracing::info!(epoch, "configuration apply recovered"),
        });
    }
    fn complete_with(&mut self, epoch: u64, result: Result, mut notify: impl FnMut(ApplyEvent<'_>)) {
        match result {
            Ok(()) => {
                if self.last_error.is_some() { notify(ApplyEvent::Recovered); }
                self.applied_epoch = Some(epoch); self.last_error = None;
            }
            Err(error) => {
                if self.last_error.as_ref() != Some(&error) { notify(ApplyEvent::Failed(&error)); }
                self.last_error = Some(error);
            }
        }
    }
}

/// Independent retry budget for one host effect. Cached errors remain visible
/// while waiting; success or a new desired epoch resets the delay.
#[derive(Default)]
pub(crate) struct Retry {
    epoch: Option<u64>,
    error: Option<ApplyError>,
    next: Option<Instant>,
    delay: u64,
}
impl Retry {
    #[cfg(test)]
    pub fn waiting(&self, epoch: u64, now: Instant) -> bool {
        self.epoch == Some(epoch) && self.next.is_some_and(|deadline| now < deadline) && self.error.is_some()
    }

    pub fn run(&mut self, epoch: u64, now: Instant, effect: impl FnOnce() -> Result) -> Result {
        if self.epoch != Some(epoch) { *self = Self { epoch: Some(epoch), ..Self::default() }; }
        if self.next.is_some_and(|t| now < t) && let Some(error) = &self.error { return Err(error.clone()); }
        let result = effect();
        match &result {
            Ok(()) => { self.error = None; self.next = None; self.delay = 0; }
            Err(error) => {
                self.delay = if self.delay == 0 { 2 } else { (self.delay * 2).min(60) };
                self.next = Some(now + Duration::from_secs(self.delay));
                self.error = Some(error.clone());
            }
        }
        result
    }
}

pub(crate) async fn blocking<T: Send + 'static>(effect: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(effect).await.map_err(|e| ApplyError::new(&["host", "spawn_blocking"], e.to_string()))?
}

/// Only call this for optional IPv6 operations, never for an IPv4 failure.
pub(crate) fn ipv6_unavailable(error: &ApplyError) -> bool {
    let message = error.stderr.to_ascii_lowercase();
    if error.kind == io::ErrorKind::PermissionDenied || message.contains("permission denied") || message.contains("operation not permitted") { return false; }
    error.kind == io::ErrorKind::NotFound || error.kind == io::ErrorKind::Unsupported
        || error.stderr.contains("Address family not supported") || error.stderr.contains("IPv6 is disabled")
        || error.stderr.contains("Operation not supported") || error.stderr.contains("Protocol not supported") || error.missing()
}

#[derive(Default)]
pub(crate) struct Routes {
    pub installed: std::collections::HashSet<String>,
    skipped: std::collections::HashMap<String, (u64, Instant, ApplyError)>,
}

pub(crate) enum RouteOutcome { Installed, Skipped(ApplyError) }

pub(crate) fn sync_routes(
    state: &mut Routes, desired: &std::collections::HashSet<String>, clock: (u64, Instant),
    mut add: impl FnMut(&str) -> Result<RouteOutcome>, mut remove: impl FnMut(&str) -> Result,
) -> Result {
    let (epoch, now) = clock;
    let mut results = Vec::new();
    state.skipped.retain(|prefix, _| desired.contains(prefix));
    let obsolete: Vec<_> = state.installed.difference(desired).cloned().collect();
    for prefix in obsolete {
        let result = remove(&prefix);
        if result.is_ok() { state.installed.remove(&prefix); }
        results.push(result);
    }
    for prefix in desired.difference(&state.installed).cloned().collect::<Vec<_>>() {
        if state.skipped.get(&prefix).is_some_and(|(old_epoch, next, _)| *old_epoch == epoch && now < *next) { continue; }
        match add(&prefix) {
            Ok(RouteOutcome::Installed) => {
                if state.skipped.remove(&prefix).is_some() { tracing::info!(%prefix, "host route recovered"); }
                state.installed.insert(prefix);
            }
            Ok(RouteOutcome::Skipped(error)) => {
                if state.skipped.get(&prefix).is_none_or(|(_, _, old)| old != &error) {
                    tracing::warn!(%prefix, %error, "optional host route unavailable; retrying in 60s or on epoch change");
                }
                state.skipped.insert(prefix, (epoch, now + Duration::from_secs(60), error));
            }
            Err(error) => { state.skipped.remove(&prefix); results.push(Err(error)); }
        }
    }
    all(results)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    pub struct Scripted {
        pub commands: Vec<Vec<String>>,
        replies: std::collections::VecDeque<Result<String>>,
    }
    impl Scripted {
        pub fn new(replies: Vec<Result<String>>) -> Self {
            Self { commands: vec![], replies: replies.into() }
        }
    }
    impl Runner for Scripted {
        fn run(&mut self, command: &[&str], _: Option<&str>) -> Result<String> {
            self.commands.push(command.iter().map(|s| s.to_string()).collect());
            self.replies.pop_front().expect("unexpected command").map_err(|mut e| { e.command = command.iter().map(|s| s.to_string()).collect(); e })
        }
    }
    pub fn error(exit_code: Option<i32>, stderr: &str) -> ApplyError {
        ApplyError { command: vec![], exit_code, stderr: stderr.into(), kind: if exit_code.is_none() { io::ErrorKind::NotFound } else { io::ErrorKind::Other } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn identical_errors_log_once_and_changes_and_recovery_log_again() {
        let mut events = Vec::new();
        let mut notify = |event: ApplyEvent<'_>| match event {
            ApplyEvent::Failed(error) => events.push(error.stderr.clone()),
            ApplyEvent::Recovered => events.push("recovered".into()),
        };
        let mut status = Status::default();
        for _ in 0..10 { status.complete_with(1, Err(ApplyError::new(&["route"], "denied")), &mut notify); }
        status.complete_with(1, Err(ApplyError::new(&["route"], "different failure")), &mut notify);
        status.complete_with(1, Ok(()), &mut notify); status.complete_with(1, Ok(()), &mut notify);
        assert_eq!(events, ["denied", "different failure", "recovered"]);
    }

    #[test]
    fn retry_backoff_is_bounded_and_resets_on_epoch_or_success() {
        let mut retry = Retry::default();
        let start = Instant::now();
        let mut calls = Vec::new();
        for second in 0..200 {
            let _result = retry.run(1, start + Duration::from_secs(second), || {
                calls.push(second); Err(ApplyError::new(&["route"], "denied"))
            });
        }
        assert_eq!(calls, [0, 2, 6, 14, 30, 62, 122, 182]);
        retry.run(2, start + Duration::from_secs(201), || Ok(())).unwrap();
        assert!(retry.error.is_none());
        retry.run(2, start + Duration::from_secs(201), || Err(ApplyError::new(&["route"], "denied"))).unwrap_err();
        assert_eq!(retry.delay, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn command_timeout_is_reaped_without_blocking_runtime() {
        let command = blocking(|| run_timeout(&["sh", "-c", "echo $$ >&2; exec sleep 60"], None, Duration::from_millis(300)));
        let task = tokio::spawn(command);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!task.is_finished(), "a blocked runtime would resume only after the command timeout");
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.kind, io::ErrorKind::TimedOut);
        assert!(error.stderr.contains("timeout after 300 ms; killed and reaped"));
        #[cfg(unix)]
        {
            let pid: i32 = error.stderr.lines().next().unwrap().parse().unwrap();
            // SAFETY: signal zero only queries the child PID recorded above.
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        }
    }

    #[test]
    fn failed_route_add_and_delete_preserve_state_and_epoch_until_retry() {
        let mut installed = Routes { installed: HashSet::from(["10.1.0.0/16".to_string()]), ..Routes::default() };
        let desired = HashSet::from(["10.2.0.0/16".to_string()]);
        let mut status = Status::default();
        status.complete(1, Ok(()));
        let result = sync_routes(&mut installed, &desired, (2, Instant::now()),
            |_| Err(ApplyError::new(&["ip", "route", "replace"], "permission denied")),
            |_| Err(ApplyError::new(&["ip", "route", "del"], "permission denied")));
        status.complete(2, result);
        assert_eq!(installed.installed, HashSet::from(["10.1.0.0/16".to_string()]));
        assert_eq!(status.applied_epoch, Some(1));
        assert!(status.last_error.is_some());
        status.complete(2, sync_routes(&mut installed, &desired, (2, Instant::now()), |_| Ok(RouteOutcome::Installed), |_| Ok(())));
        assert_eq!(installed.installed, desired);
        assert_eq!(status.applied_epoch, Some(2));
        assert!(status.last_error.is_none());
    }

    #[test]
    fn real_runner_preserves_exit_code_stderr_and_missing_program() {
        let err = System.run(&["sh", "-c", "printf 'permission denied' >&2; exit 7"], None).unwrap_err();
        assert_eq!(err.exit_code, Some(7));
        assert_eq!(err.stderr, "permission denied");
        assert_eq!(err.command.first().map(String::as_str), Some("sh"));
        let err = System.run(&["/nonexistent-fluxpeer-command"], None).unwrap_err();
        assert_eq!(err.kind, io::ErrorKind::NotFound);
        assert_eq!(err.exit_code, None);
    }
    #[cfg(unix)]
    #[test]
    fn busy_or_cross_device_rename_preserves_inode_and_writes_in_place() {
        use std::os::unix::fs::MetadataExt;
        for errno in [libc::EBUSY, libc::EXDEV] {
            let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("resolver");
            std::fs::write(&path, b"original longer content").unwrap();
            let inode = std::fs::metadata(&path).unwrap().ino();
            write_file_with(&path, b"new", |_| Ok(false), |_, _| Err(io::Error::from_raw_os_error(errno))).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"new");
            assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        }
    }
    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_owner_and_labeled_target_uses_original_inode() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("resolver");
        std::fs::write(&path, b"original").unwrap();
        let before = std::fs::metadata(&path).unwrap();
        write_file_with(&path, b"atomic", |_| Ok(false), |from, to| std::fs::rename(from, to)).unwrap();
        let atomic = std::fs::metadata(&path).unwrap();
        assert_ne!(before.ino(), atomic.ino()); assert_eq!((before.uid(), before.gid()), (atomic.uid(), atomic.gid()));
        write_file_with(&path, b"labeled", |_| Ok(true), |_, _| panic!("labeled target must not rename")).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), atomic.ino());
        assert_eq!(std::fs::read(&path).unwrap(), b"labeled");
        assert!(write_file_with(&path, b"denied", |_| Ok(false), |_, _| Err(io::Error::from(io::ErrorKind::PermissionDenied))).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"labeled");
    }

}

