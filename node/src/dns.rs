//! Pluggable DNS backend for full-tunnel exit clients.
//!
//! OpenWrt manages resolver state through UCI/dnsmasq, while generic Linux uses
//! systemd-resolved when available and falls back to direct `/etc/resolv.conf`.

use std::collections::HashMap;
use crate::apply::{self, Result};

const STATE_PATH: &str = "/run/fluxpeer-dns.state";

pub trait Dns {
    fn name(&self) -> &'static str;
    fn set(&self, dns: &str) -> Result;
    fn clear(&self) -> Result;
}

pub struct OpenWrtDnsmasq;
pub struct Resolvectl {
    iface: Option<String>,
}
pub struct ResolvConf;

pub fn detect() -> Box<dyn Dns> {
    detect_for_iface(None)
}

pub(crate) fn detect_for_iface(iface: Option<&str>) -> Box<dyn Dns> {
    match std::env::var("FLUXPEER_DNS_BACKEND").ok().as_deref() {
        Some("openwrt" | "dnsmasq" | "uci") => return Box::new(OpenWrtDnsmasq),
        Some("resolvectl") => return Box::new(Resolvectl::new(iface)),
        Some("resolv" | "resolvconf") => return Box::new(ResolvConf),
        Some(other) if !other.is_empty() => tracing::warn!(backend = other, "unknown FLUXPEER_DNS_BACKEND"),
        _ => {}
    }

    if command_exists("uci") && std::path::Path::new("/etc/config/dhcp").exists() {
        return Box::new(OpenWrtDnsmasq);
    }
    if command_exists("resolvectl") {
        return Box::new(Resolvectl::new(iface));
    }
    Box::new(ResolvConf)
}

fn command_exists(bin: &str) -> bool {
    apply::output(&["sh", "-c", &format!("command -v {bin}")]).is_ok()
}

fn uci_get(key: &str) -> Result<Option<String>> {
    match apply::output(&["uci", "get", key]) {
        Ok(value) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Err(e) if e.exit_code == Some(1) && e.stderr.contains("Entry not found") => Ok(None),
        Err(e) => Err(e),
    }
}

fn restart_dnsmasq() -> Result { apply::run(&["/etc/init.d/dnsmasq", "restart"]) }

fn read_state() -> Result<HashMap<String, String>> {
    let mut state = HashMap::new();
    let raw = match std::fs::read_to_string(STATE_PATH) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(state),
        Err(e) => return Err(apply::ApplyError::io(&["read", STATE_PATH], e)),
    };
    for line in raw.lines() {
        if let Some((key, value)) = line.split_once('=') {
            state.insert(key.to_string(), value.to_string());
        }
    }
    Ok(state)
}

fn write_state(state: &HashMap<String, String>) -> Result {
    let mut entries: Vec<_> = state.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    let body: String = entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect();
    apply::write(STATE_PATH, body)
}

fn remove_state() -> Result { apply::remove(STATE_PATH) }

impl Dns for OpenWrtDnsmasq {
    fn name(&self) -> &'static str {
        "openwrt-dnsmasq"
    }

    fn set(&self, dns: &str) -> Result {
        let mut state = read_state()?;
        if !state.contains_key("had_noresolv") {
            if let Some(value) = uci_get("dhcp.@dnsmasq[0].noresolv")? {
                state.insert("had_noresolv".to_string(), "1".to_string());
                state.insert("noresolv".to_string(), value);
            } else {
                state.insert("had_noresolv".to_string(), "0".to_string());
            }
        }
        state.insert("dns".to_string(), dns.to_string());
        write_state(&state)?;

        apply::run(&["uci", "set", "dhcp.@dnsmasq[0].noresolv=1"])?;
        let servers = uci_get("dhcp.@dnsmasq[0].server")?.unwrap_or_default();
        if !servers.split_whitespace().any(|server| server == dns) {
            let arg = format!("dhcp.@dnsmasq[0].server={dns}");
            apply::run(&["uci", "add_list", &arg])?;
        }
        apply::run(&["uci", "commit", "dhcp"])?;
        restart_dnsmasq()?;
        tracing::info!(dns, "exit DNS via OpenWrt dnsmasq");
        Ok(())
    }

    fn clear(&self) -> Result {
        let state = read_state()?;
        if let Some(dns) = state.get("dns") {
            let arg = format!("dhcp.@dnsmasq[0].server={dns}");
            apply::run(&["uci", "del_list", &arg])?;
        }
        match state.get("had_noresolv").map(String::as_str) {
            Some("1") => {
                let value = state.get("noresolv").map(String::as_str).unwrap_or("0");
                let arg = format!("dhcp.@dnsmasq[0].noresolv={value}");
                apply::run(&["uci", "set", &arg])?;
            }
            Some("0") => {
                apply::run(&["uci", "delete", "dhcp.@dnsmasq[0].noresolv"])?;
            }
            _ => {}
        }
        apply::run(&["uci", "commit", "dhcp"])?;
        restart_dnsmasq()?;
        remove_state()?;
        tracing::info!("exit DNS cleared via OpenWrt dnsmasq");
        Ok(())
    }
}

fn resolved_unavailable(error: &apply::ApplyError) -> bool {
    let message = error.stderr.to_ascii_lowercase();
    error.kind == std::io::ErrorKind::NotFound || ["failed to connect to bus", "failed to connect to system bus", "connection refused", "serviceunknown",
        "not provided by any .service", "resolve1.service not found", "systemd-resolved is not running", "dbus is not running"]
        .iter().any(|needle| message.contains(needle))
}

fn resolv_conf_with(runner: &mut impl apply::Runner, dns: &str) -> Result {
    runner.write("/etc/resolv.conf", &format!("# fluxpeer exit-node\nnameserver {dns}\n"))
}

impl Resolvectl {
    fn new(iface: Option<&str>) -> Self {
        Self {
            iface: iface.map(ToString::to_string),
        }
    }

    fn set_with(&self, dns: &str, runner: &mut impl apply::Runner) -> Result {
        let iface = self.iface();
        let result = runner.run(&["resolvectl", "dns", iface, dns], None)
            .and_then(|_| runner.run(&["resolvectl", "domain", iface, "~."], None));
        match result {
            Ok(_) => { tracing::info!(iface, dns, "exit DNS via resolvectl"); Ok(()) }
            Err(e) if resolved_unavailable(&e) => {
                tracing::warn!(%e, "resolved unavailable; using resolv.conf fallback");
                resolv_conf_with(runner, dns)
            }
            Err(e) => Err(e),
        }
    }

    fn iface(&self) -> &str {
        self.iface.as_deref().unwrap_or("fluxpeer")
    }
}

impl Dns for Resolvectl {
    fn name(&self) -> &'static str {
        "resolvectl"
    }

    fn set(&self, dns: &str) -> Result {
        self.set_with(dns, &mut apply::System)
    }

    fn clear(&self) -> Result {
        let iface = self.iface();
        match apply::run(&["resolvectl", "revert", iface]) {
            Err(e) if resolved_unavailable(&e) => { tracing::warn!(%e, "resolved unavailable during cleanup"); ResolvConf.clear() }
            result => result,
        }
    }
}

impl Dns for ResolvConf {
    fn name(&self) -> &'static str {
        "resolv"
    }

    fn set(&self, dns: &str) -> Result {
        resolv_conf_with(&mut apply::System, dns)?;
        tracing::info!(dns, "exit DNS via /etc/resolv.conf");
        Ok(())
    }

    fn clear(&self) -> Result {
        tracing::warn!("resolv.conf DNS backend has no saved previous resolver state (T-0028)");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FailingRunner { fail: bool, commands: Vec<Vec<String>> }
    impl apply::Runner for FailingRunner {
        fn run(&mut self, command: &[&str], _: Option<&str>) -> Result<String> {
            self.commands.push(command.iter().map(|s| s.to_string()).collect());
            if self.fail && command.get(1) == Some(&"domain") {
                Err(apply::ApplyError::new(command, "resolver unavailable"))
            } else { Ok(String::new()) }
        }
    }

    #[test]
    fn unavailable_resolved_falls_back_but_permission_errors_remain_visible() {
        use apply::test_support::{Scripted, error};
        for replies in [vec![Err(error(Some(1), "Failed to connect to bus: No such file or directory"))],
            vec![Ok("".into()), Err(error(Some(1), "org.freedesktop.DBus.Error.ServiceUnknown"))]] {
            let mut runner = Scripted::new(replies);
            Resolvectl::new(Some("fp0")).set_with("100.72.16.1", &mut runner).unwrap();
            assert_eq!(runner.commands[0], ["resolvectl", "dns", "fp0", "100.72.16.1"]);
            assert_eq!(runner.writes, [("/etc/resolv.conf".into(), "# fluxpeer exit-node\nnameserver 100.72.16.1\n".into())]);
        }
        let mut runner = Scripted::new(vec![Err(error(Some(1), "Access denied"))]);
        assert!(Resolvectl::new(Some("fp0")).set_with("100.72.16.1", &mut runner).is_err());
        assert!(runner.writes.is_empty());
        let mut runner = Scripted::new(vec![Err(error(Some(1), "Connection refused"))]);
        runner.write_error = Some(apply::ApplyError::new(&["write", "/etc/resolv.conf"], "read-only file system"));
        assert_eq!(Resolvectl::new(Some("fp0")).set_with("100.72.16.1", &mut runner).unwrap_err().command, ["write", "/etc/resolv.conf"]);
    }

    #[test]
    fn dns_domain_failure_is_visible_and_retry_replays_both_commands() {
        let backend = Resolvectl::new(Some("fp-test"));
        let mut runner = FailingRunner { fail: true, commands: vec![] };
        let error = backend.set_with("100.72.16.1", &mut runner).unwrap_err();
        assert_eq!(error.command, ["resolvectl", "domain", "fp-test", "~."]);
        assert_eq!(runner.commands.len(), 2);
        runner.fail = false;
        backend.set_with("100.72.16.1", &mut runner).unwrap();
        assert_eq!(runner.commands.len(), 4);
        assert_eq!(runner.commands[0], runner.commands[2]);
        assert_eq!(runner.commands[1], runner.commands[3]);
    }
}
