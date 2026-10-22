// SPDX-License-Identifier: BSD-3-Clause
//! Member process ownership, exit observation and exclusive lifecycle operations.
use std::{collections::{HashMap, HashSet}, io, sync::Arc};
#[cfg(unix)]
use std::time::Duration;
use parking_lot::Mutex;
use tokio::{process::{Child, Command}, sync::watch};

#[derive(Clone, Default)]
pub(super) struct ExitInfo {
    pub code: Option<i32>,
    pub last_error: Option<String>,
    pub forced: bool,
    cleanup_failed: bool,
}
#[derive(Clone)]
struct Member { stop: watch::Sender<bool>, done: watch::Receiver<Option<ExitInfo>> }
#[derive(Default)]
struct State {
    members: HashMap<String, Member>,
    exits: HashMap<String, ExitInfo>,
    busy: HashSet<String>,
    cleanup: HashSet<String>,
    closing: bool,
}
#[derive(Default)]
pub(super) struct Processes { state: Arc<Mutex<State>> }
pub(super) struct Operation { state: Arc<Mutex<State>>, iface: Option<String>, committed: bool }
impl Operation {
    pub fn commit(mut self) { self.committed = true; }
}
impl Drop for Operation {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        if let Some(iface) = &self.iface { state.busy.remove(iface); }
        else if !self.committed { state.closing = false; }
    }
}
fn busy() -> io::Error { io::Error::new(io::ErrorKind::WouldBlock, "network lifecycle busy") }
impl Processes {
    pub fn operation(&self, iface: &str) -> io::Result<Operation> {
        let mut state = self.state.lock();
        if state.closing || !state.busy.insert(iface.to_string()) { return Err(busy()); }
        Ok(Operation { state: self.state.clone(), iface: Some(iface.into()), committed: false })
    }
    pub fn quiesce(&self) -> io::Result<Operation> {
        let mut state = self.state.lock();
        if state.closing || !state.busy.is_empty() { return Err(busy()); }
        state.closing = true;
        Ok(Operation { state: self.state.clone(), iface: None, committed: false })
    }
    pub fn contains(&self, iface: &str) -> bool { self.state.lock().members.contains_key(iface) }
    pub fn running(&self, iface: &str) -> io::Result<bool> {
        match self.state.lock().members.get(iface) {
            Some(member) if *member.stop.borrow() => Err(busy()),
            Some(_) => Ok(true), None => Ok(false),
        }
    }
    pub fn ifaces(&self) -> Vec<String> { self.state.lock().members.keys().cloned().collect() }
    pub fn snapshot(&self, iface: &str) -> (bool, Option<ExitInfo>) {
        let state = self.state.lock(); (state.members.contains_key(iface), state.exits.get(iface).cloned())
    }
    pub fn cleanup_ifaces(&self) -> Vec<String> { self.state.lock().cleanup.iter().cloned().collect() }
    pub fn needs_cleanup(&self, iface: &str) -> bool { self.state.lock().cleanup.contains(iface) }
    pub fn cleaned(&self, iface: &str) { self.state.lock().cleanup.remove(iface); }
    pub fn spawn(&self, iface: &str, cmd: &mut Command) -> io::Result<()> {
        let mut state = self.state.lock();
        if state.closing { return Err(busy()); }
        if let Some(member) = state.members.get(iface) {
            return if *member.stop.borrow() { Err(busy()) } else { Ok(()) };
        }
        let child = match cmd.kill_on_drop(true).spawn() {
            Ok(child) => child,
            Err(error) => {
                state.exits.insert(iface.into(), ExitInfo { last_error: Some(error.to_string()), ..ExitInfo::default() });
                return Err(error);
            }
        };
        let (stop, rx) = watch::channel(false);
        let (done, result) = watch::channel(None);
        state.exits.remove(iface);
        state.cleanup.insert(iface.into());
        state.members.insert(iface.into(), Member { stop, done: result });
        let state = Arc::downgrade(&self.state); let iface = iface.to_string();
        tokio::spawn(async move {
            let info = supervise(child, rx).await;
            tracing::info!(%iface, exit_code = ?info.code, forced = info.forced, error = ?info.last_error, "network process exited");
            // Keep removal + exit history atomic; a new start cannot be removed by
            // this generation's completion or inherit its exit status.
            if let Some(state) = state.upgrade() {
                let mut state = state.lock();
                state.members.remove(&iface);
                state.exits.insert(iface, info.clone());
                done.send_replace(Some(info));
            }
        });
        Ok(())
    }
    pub async fn stop(&self, iface: &str) -> io::Result<()> {
        let member = self.state.lock().members.get(iface).cloned();
        if let Some(mut member) = member {
            member.stop.send_replace(true);
            let info = member.done.wait_for(|value| value.is_some()).await
                .map_err(|_| io::Error::other("member supervisor stopped without an exit result"))?.clone();
            if let Some(error) = info.and_then(|info| info.last_error) { return Err(io::Error::other(error)); }
        } else if let Some(info) = self.snapshot(iface).1
            && info.cleanup_failed {
            return Err(io::Error::other(info.last_error.unwrap_or_else(|| "forced termination; cleanup unverified".into())));
        }
        Ok(())
    }
}

async fn supervise(mut child: Child, mut stop: watch::Receiver<bool>) -> ExitInfo {
    let mut requested = false;
    let mut forced = false;
    let result = tokio::select! {
        result = child.wait() => result,
        _ = stop.changed() => {
            requested = true;
            #[cfg(unix)]
            {
                if let Some(pid) = child.id() {
                    // The Child remains owned and unreaped here, so its pid
                    // cannot be reused by an unrelated process before signalling.
                    let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
                    if rc != 0 { tracing::warn!(error = %io::Error::last_os_error(), "member SIGTERM failed"); }
                }
                match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
                    Ok(result) => result,
                    Err(_) => { forced = true; force_and_wait(&mut child).await },
                }
            }
            #[cfg(not(unix))]
            { forced = true; force_and_wait(&mut child).await }
        }
    };
    match result {
        Ok(status) => ExitInfo {
            code: status.code(), forced,
            cleanup_failed: forced || (!status.success() && (!requested || status.code().is_some())),
            last_error: if forced { Some("forced termination; network cleanup may be incomplete".into()) }
                else if !status.success() && (!requested || status.code().is_some()) { Some(format!("network process exited: {status}")) }
                else { None },
        },
        Err(error) => ExitInfo { last_error: Some(format!("member wait failed: {error}")), forced, code: None, cleanup_failed: true },
    }
}
async fn force_and_wait(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    child.start_kill()?;
    child.wait().await
}
