// SPDX-License-Identifier: BSD-3-Clause
//! Persistent per-interface leases; the last owner restores the saved sysctls.
//! The file lock is shared by independent node processes, not just threads.

use super::{apply, ApplyError, Result, sysctl_get_with, sysctl_set_with};
use std::{fs::{self, File, OpenOptions}, io::{self, Write}, path::{Path, PathBuf}, time::{Duration, Instant}};

#[derive(serde::Serialize, serde::Deserialize)]
struct Baseline { v4: bool, v6: Option<bool> }

pub(super) struct State { root: PathBuf, _lock: File }

impl Drop for State {
    fn drop(&mut self) {
        // Explicit unlock releases the open-file-description lock even if a
        // concurrently forked command temporarily inherited the CLOEXEC fd.
        if let Err(error) = self._lock.unlock() {
            tracing::warn!(%error, path = %self.root.display(), "failed to unlock forwarding state");
        }
    }
}

impl State {
    pub(super) fn lock(root: &Path) -> Result<Self> { Self::lock_for(root, Duration::from_secs(10)) }

    fn lock_for(root: &Path, timeout: Duration) -> Result<Self> {
        fs::create_dir_all(root).map_err(|e| file_error("mkdir", root, e))?;
        let path = root.join("lock");
        let file = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(&path).map_err(|e| file_error("open", &path, e))?;
        let deadline = Instant::now() + timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { root: root.to_path_buf(), _lock: file }),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Err(std::fs::TryLockError::WouldBlock) => return Err(file_error("lock", &path, io::Error::new(io::ErrorKind::TimedOut, format!("forwarding lock contention: another instance holds the firewall state lock; timed out after {} ms", timeout.as_millis())))),
                Err(std::fs::TryLockError::Error(e)) => return Err(file_error("lock", &path, e)),
            }
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn acquire(&self, runner: &mut impl apply::Runner, id: &str) -> Result {
        self.acquire_with(runner, id, "net.ipv4.ip_forward", Some("net.ipv6.conf.all.forwarding"))
    }

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn acquire_macos(&self, runner: &mut impl apply::Runner, id: &str) -> Result {
        self.acquire_with(runner, id, "net.inet.ip.forwarding", None)
    }

    fn acquire_with(&self, runner: &mut impl apply::Runner, id: &str, v4: &str, v6: Option<&str>) -> Result {
        let path = self.root.join("baseline.json");
        let baseline = match self.baseline()? {
            Some(mut baseline) => {
                if baseline.v6.is_none() { baseline.v6 = read_v6(runner, v6)?; }
                baseline
            },
            None => {
                if self.leases()?.next().is_some() { return Err(ApplyError::new(&["forwarding", "acquire"], "leases exist without baseline; refusing to overwrite original state")); }
                Baseline { v4: sysctl_get_with(runner, v4)?, v6: read_v6(runner, v6)? }
            }
        };
        self.save(&path, &serde_json::to_vec(&baseline).map_err(|e| ApplyError::new(&["forwarding", "serialize"], e.to_string()))?)?;
        // Persist ownership before any mutation. Retries cannot accidentally
        // replace the original baseline with the already-enabled value.
        self.save(&self.root.join(format!("{id}.lease")), b"forwarding\n")?;
        sysctl_set_with(runner, v4, true)?;
        if let Some(key) = v6 && baseline.v6.is_some() { sysctl_set_with(runner, key, true)?; }
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn release(&self, runner: &mut impl apply::Runner, id: &str) -> Result {
        self.release_with(runner, id, "net.ipv4.ip_forward", Some("net.ipv6.conf.all.forwarding"))
    }

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn release_macos(&self, runner: &mut impl apply::Runner, id: &str) -> Result {
        self.release_with(runner, id, "net.inet.ip.forwarding", None)
    }

    fn release_with(&self, runner: &mut impl apply::Runner, id: &str, v4: &str, v6: Option<&str>) -> Result {
        let lease = self.root.join(format!("{id}.lease"));
        let leases: Vec<_> = self.leases()?.collect();
        if !leases.contains(&lease) { return Ok(()); }
        if leases.iter().any(|p| p != &lease) { return remove(&lease); }
        let baseline = self.baseline()?.ok_or_else(|| ApplyError::new(&["forwarding", "release"], "missing forwarding baseline"))?;
        let v4 = sysctl_set_with(runner, v4, baseline.v4);
        let v6 = baseline.v6.zip(v6).map_or(Ok(()), |(on, key)| sysctl_set_with(runner, key, on));
        apply::all([v4, v6])?;
        // Keep both records on a failed restore. With the lock held, no other
        // instance can race the last-owner check or capture a partial restore.
        remove(&lease)?;
        remove(&self.root.join("baseline.json"))
    }

    fn baseline(&self) -> Result<Option<Baseline>> {
        let path = self.root.join("baseline.json");
        match fs::read(&path) {
            Ok(data) => serde_json::from_slice(&data).map(Some).map_err(|e| ApplyError::new(&["read", &path.to_string_lossy()], format!("invalid forwarding baseline: {e}"))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(file_error("read", &path, e)),
        }
    }

    fn leases(&self) -> Result<impl Iterator<Item = PathBuf>> {
        let mut leases = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|e| file_error("read_dir", &self.root, e))? {
            let path = entry.map_err(|e| file_error("read_dir", &self.root, e))?.path();
            if path.extension().is_some_and(|s| s == "lease") { leases.push(path); }
        }
        Ok(leases.into_iter())
    }

    pub(super) fn save(&self, path: &Path, bytes: &[u8]) -> Result {
        let mut temp = tempfile::NamedTempFile::new_in(&self.root).map_err(|e| file_error("create", path, e))?;
        temp.write_all(bytes).map_err(|e| file_error("write", path, e))?;
        temp.as_file().sync_all().map_err(|e| file_error("sync", path, e))?;
        temp.persist(path).map_err(|e| file_error("rename", path, e.error))?;
        File::open(&self.root).and_then(|dir| dir.sync_all()).map_err(|e| file_error("sync", &self.root, e))
    }
}

fn read_v6(runner: &mut impl apply::Runner, key: Option<&str>) -> Result<Option<bool>> {
    let Some(key) = key else { return Ok(None); };
    match sysctl_get_with(runner, key) {
        Ok(on) => Ok(Some(on)),
        Err(e) if apply::ipv6_unavailable(&e) => { tracing::warn!(%e, "IPv6 forwarding unavailable"); Ok(None) }
        Err(e) => Err(e),
    }
}
fn remove(path: &Path) -> Result {
    match fs::remove_file(path) { Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()), result => result.map_err(|e| file_error("remove", path, e)) }
}
fn file_error(op: &str, path: &Path, error: io::Error) -> ApplyError { ApplyError::io(&[op, &path.to_string_lossy()], error) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::Runner;
    use std::collections::HashMap;

    struct Sysctl { values: HashMap<String, bool>, writes: Vec<String>, fail_restore: bool }
    impl Sysctl {
        fn new(v4: bool, v6: bool) -> Self {
            Self { values: HashMap::from([("net.ipv4.ip_forward".into(), v4), ("net.ipv6.conf.all.forwarding".into(), v6)]), writes: vec![], fail_restore: false }
        }
    }
    impl Runner for Sysctl {
        fn run(&mut self, args: &[&str], _: Option<&str>) -> Result<String> {
            match args {
                ["sysctl", "-n", key] => Ok(u8::from(self.values[*key]).to_string()),
                ["sysctl", "-w", value] => {
                    let (key, value) = value.split_once('=').unwrap();
                    if self.fail_restore && value == "0" { return Err(ApplyError::new(args, "Permission denied")); }
                    self.values.insert(key.into(), value == "1");
                    self.writes.push(format!("{key}={value}"));
                    Ok(String::new())
                }
                _ => panic!("unexpected command: {args:?}"),
            }
        }
    }

    #[test]
    fn two_instances_restart_retry_and_stop_in_either_order_preserve_forwarding() {
        for order in [["a", "b"], ["b", "a"]] {
            for initial in [(false, false), (true, false), (true, true)] {
                let dir = tempfile::tempdir().unwrap();
                let mut host = Sysctl::new(initial.0, initial.1);
                // Each lock represents a different daemon process/restart.
                State::lock(dir.path()).unwrap().acquire(&mut host, "a").unwrap();
                State::lock(dir.path()).unwrap().acquire(&mut host, "b").unwrap();
                State::lock(dir.path()).unwrap().acquire(&mut host, "a").unwrap();
                assert_eq!(fs::read_dir(dir.path()).unwrap().flatten().filter(|p| p.path().extension().is_some_and(|s| s == "lease")).count(), 2);
                State::lock(dir.path()).unwrap().release(&mut host, order[0]).unwrap();
                assert!(host.values.values().all(|v| *v));
                State::lock(dir.path()).unwrap().release(&mut host, order[0]).unwrap();
                assert!(host.values.values().all(|v| *v));
                State::lock(dir.path()).unwrap().release(&mut host, order[1]).unwrap();
                assert_eq!(host.values["net.ipv4.ip_forward"], initial.0);
                assert_eq!(host.values["net.ipv6.conf.all.forwarding"], initial.1);
                assert!(!dir.path().join("baseline.json").exists());
            }
        }
    }

    #[test]
    fn failed_restore_keeps_lease_and_baseline_until_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = Sysctl::new(false, false);
        State::lock(dir.path()).unwrap().acquire(&mut host, "a").unwrap();
        host.fail_restore = true;
        assert!(State::lock(dir.path()).unwrap().release(&mut host, "a").is_err());
        assert!(dir.path().join("a.lease").exists());
        assert!(dir.path().join("baseline.json").exists());
        // A second owner arriving during failed cleanup still uses the original baseline.
        State::lock(dir.path()).unwrap().acquire(&mut host, "b").unwrap();
        State::lock(dir.path()).unwrap().release(&mut host, "a").unwrap();
        host.fail_restore = false;
        State::lock(dir.path()).unwrap().release(&mut host, "b").unwrap();
        assert!(host.values.values().all(|v| !*v));
    }

    #[test]
    fn missing_ipv6_is_not_mutated_without_baseline_and_later_owner_can_enable_it() {
        use apply::test_support::{Scripted, error};
        let dir = tempfile::tempdir().unwrap();
        let mut missing = Scripted::new(vec![Ok("0".into()), Err(error(None, "No such file or directory")), Ok("0".into()), Ok(String::new())]);
        State::lock(dir.path()).unwrap().acquire(&mut missing, "a").unwrap();
        assert_eq!(missing.commands.last().unwrap(), &["sysctl", "-w", "net.ipv4.ip_forward=1"]);
        let mut host = Sysctl::new(true, false);
        State::lock(dir.path()).unwrap().acquire(&mut host, "b").unwrap();
        assert!(host.values.values().all(|v| *v));
        State::lock(dir.path()).unwrap().release(&mut host, "a").unwrap();
        State::lock(dir.path()).unwrap().release(&mut host, "b").unwrap();
        assert!(host.values.values().all(|v| !*v));
    }

    #[test]
    fn corrupt_baseline_or_unreadable_value_never_overwrites_saved_ownership() {
        use apply::test_support::Scripted;
        let dir = tempfile::tempdir().unwrap();
        let mut invalid = Scripted::new(vec![Ok("unknown".into())]);
        assert!(State::lock(dir.path()).unwrap().acquire(&mut invalid, "a").is_err());
        assert!(!dir.path().join("a.lease").exists());
        fs::write(dir.path().join("baseline.json"), "broken").unwrap();
        let mut runner = Scripted::new(vec![]);
        assert!(State::lock(dir.path()).unwrap().acquire(&mut runner, "a").is_err());
        assert_eq!(fs::read_to_string(dir.path().join("baseline.json")).unwrap(), "broken");
    }

    #[cfg(unix)]
    #[test]
    fn explicit_unlock_hands_off_while_child_inherits_lock_descriptor() {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let dir = tempfile::tempdir().unwrap();
        let held = State::lock(dir.path()).unwrap();
        let fd = held._lock.as_raw_fd();
        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        // SAFETY: the child-only pre-exec callback calls only async-signal-safe
        // fcntl and reads errno on failure. No allocator or lock is used.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 { return Err(io::Error::last_os_error()); }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(held);
        let other = File::open(dir.path().join("lock")).unwrap();
        let result = other.try_lock();
        child.kill().unwrap(); child.wait().unwrap();
        assert!(result.is_ok(), "an inherited fd must not extend the state lock lifetime: {result:?}");
    }

    #[test]
    fn independent_file_handles_serialize_concurrent_owners() {
        let dir = tempfile::tempdir().unwrap();
        let held = State::lock(dir.path()).unwrap();
        let error = State::lock_for(dir.path(), Duration::ZERO).err().unwrap();
        assert_eq!(error.kind, io::ErrorKind::TimedOut);
        assert!(error.stderr.contains("lock contention"));
        assert!(error.stderr.contains("another instance"));
        let other = File::open(dir.path().join("lock")).unwrap();
        assert!(matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
        drop(held);
        other.try_lock().unwrap();
        drop(other);
        let host = std::sync::Arc::new(parking_lot::Mutex::new(Sysctl::new(false, false)));
        let threads: Vec<_> = ["a", "b"].into_iter().map(|id| {
            let root = dir.path().to_path_buf(); let host = host.clone();
            std::thread::spawn(move || State::lock(&root).unwrap().acquire(&mut *host.lock(), id).unwrap())
        }).collect();
        for thread in threads { thread.join().unwrap(); }
        State::lock(dir.path()).unwrap().release(&mut *host.lock(), "a").unwrap();
        assert!(host.lock().values.values().all(|v| *v));
        State::lock(dir.path()).unwrap().release(&mut *host.lock(), "b").unwrap();
        assert!(host.lock().values.values().all(|v| !*v));
    }
}
