//! Pluggable DNS backend for full-tunnel exit clients.
//!
//! OpenWrt manages resolver state through UCI/dnsmasq, while generic Linux uses
//! systemd-resolved when available and falls back to direct `/etc/resolv.conf`.

mod managed;
use managed::Managed;
use std::collections::HashMap;
use crate::apply::{self, Result};

const STATE_PATH: &str = "/run/fluxpeer-dns.state";

pub trait Dns {
    fn name(&self) -> &'static str;
    fn set(&self, dns: &str) -> Result;
    fn clear(&self) -> Result;
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn set_mode(&self, dns: &str, _full_tunnel: bool) -> Result { self.set(dns) }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn owned(&self) -> Result<bool> { Ok(!read_state()?.is_empty()) }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn verify_file(&self) -> Result { Ok(()) }
}

pub struct OpenWrtDnsmasq;

pub fn detect() -> Box<dyn Dns> {
    detect_for_iface(None)
}

pub(crate) fn detect_for_iface(iface: Option<&str>) -> Box<dyn Dns> {
    match std::env::var("FLUXPEER_DNS_BACKEND").ok().as_deref() {
        Some("openwrt" | "dnsmasq" | "uci") => return Box::new(OpenWrtDnsmasq),
        Some("resolvectl") => return Box::new(Managed::new(iface, true)),
        Some("resolv" | "resolvconf") => return Box::new(Managed::new(iface, false)),
        Some(other) if !other.is_empty() => tracing::warn!(backend = other, "unknown FLUXPEER_DNS_BACKEND"),
        _ => {}
    }

    if command_exists("uci") && std::path::Path::new("/etc/config/dhcp").exists() {
        return Box::new(OpenWrtDnsmasq);
    }
    if command_exists("resolvectl") {
        return Box::new(Managed::new(iface, true));
    }
    Box::new(Managed::new(iface, false))
}

fn command_exists(bin: &str) -> bool {
    apply::output(&["sh", "-c", &format!("command -v {bin}")]).is_ok()
}

fn uci_get_with(key: &str, runner: &mut impl apply::Runner) -> Result<Option<String>> {
    match runner.run(&["uci", "get", key], None) {
        Ok(value) => Ok(Some(value.trim().to_string()).filter(|s| !s.is_empty())),
        Err(e) if e.exit_code == Some(1) && e.stderr.contains("Entry not found") => Ok(None),
        Err(e) => Err(e),
    }
}


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

fn openwrt_unchanged(state: &HashMap<String, String>, dns: &str) -> bool {
    state.get("applied").is_some_and(|v| v == "1") && state.get("dns").is_some_and(|value| value == dns)
}

impl Dns for OpenWrtDnsmasq {
    fn name(&self) -> &'static str {
        "openwrt-dnsmasq"
    }

    fn set(&self, dns: &str) -> Result {
        let mut state = read_state()?;
        set_openwrt_with(&mut state, dns, &mut apply::System, write_state)
    }

    fn clear(&self) -> Result {
        let state = read_state()?;
        clear_openwrt_with(&state, &mut apply::System)?;
        if !state.is_empty() { remove_state()?; }
        Ok(())
    }

}

fn set_openwrt_with(state: &mut HashMap<String, String>, dns: &str, runner: &mut impl apply::Runner,
    mut save: impl FnMut(&HashMap<String, String>) -> Result) -> Result {
    // Only a completed apply can skip commands; a saved partial operation
    // must retry even if its requested address has not changed.
    if openwrt_unchanged(state, dns) { return Ok(()); }
    state.remove("applied");
    if !state.contains_key("had_noresolv") {
        if let Some(value) = uci_get_with("dhcp.@dnsmasq[0].noresolv", runner)? {
            state.insert("had_noresolv".to_string(), "1".to_string());
            state.insert("noresolv".to_string(), value);
        } else {
            state.insert("had_noresolv".to_string(), "0".to_string());
        }
    }
    state.insert("dns".to_string(), dns.to_string());
    save(state)?;

    runner.run(&["uci", "set", "dhcp.@dnsmasq[0].noresolv=1"], None)?;
    let servers = uci_get_with("dhcp.@dnsmasq[0].server", runner)?.unwrap_or_default();
    if !servers.split_whitespace().any(|server| server == dns) {
        let arg = format!("dhcp.@dnsmasq[0].server={dns}");
        runner.run(&["uci", "add_list", &arg], None)?;
    }
    runner.run(&["uci", "commit", "dhcp"], None)?;
    runner.run(&["/etc/init.d/dnsmasq", "restart"], None)?;
    state.insert("applied".into(), "1".into());
    save(state)?;
    tracing::info!(dns, "exit DNS via OpenWrt dnsmasq");
    Ok(())
}

fn clear_openwrt_with(state: &HashMap<String, String>, runner: &mut impl apply::Runner) -> Result {
    if state.is_empty() { return Ok(()); }
    if let Some(dns) = state.get("dns") {
        let arg = format!("dhcp.@dnsmasq[0].server={dns}");
        runner.run(&["uci", "del_list", &arg], None)?;
    }
    match state.get("had_noresolv").map(String::as_str) {
        Some("1") => {
            let value = state.get("noresolv").map(String::as_str).unwrap_or("0");
            let arg = format!("dhcp.@dnsmasq[0].noresolv={value}");
            runner.run(&["uci", "set", &arg], None)?;
        }
        Some("0") => { runner.run(&["uci", "delete", "dhcp.@dnsmasq[0].noresolv"], None)?; }
        _ => {}
    }
    runner.run(&["uci", "commit", "dhcp"], None)?;
    runner.run(&["/etc/init.d/dnsmasq", "restart"], None)?;
    tracing::info!("exit DNS cleared via OpenWrt dnsmasq");
    Ok(())
}

fn resolved_unavailable(error: &apply::ApplyError) -> bool {
    let message = error.stderr.to_ascii_lowercase();
    error.kind == std::io::ErrorKind::NotFound || ["failed to connect to bus", "failed to connect to system bus", "connection refused", "serviceunknown",
        "not provided by any .service", "resolve1.service not found", "systemd-resolved is not running", "dbus is not running"]
        .iter().any(|needle| message.contains(needle))
}

#[cfg(test)]
mod tests {
    #[test]
    fn openwrt_empty_state_performs_no_commands() {
        let mut runner = crate::apply::test_support::Scripted::new(vec![]);
        super::clear_openwrt_with(&Default::default(), &mut runner).unwrap();
        assert!(runner.commands.is_empty());
    }
    #[test]
    fn openwrt_unchanged_completed_set_has_no_commands_or_state_writes() {
        let mut state = std::collections::HashMap::from([("dns".into(), "192.0.2.53".into()), ("applied".into(), "1".into()), ("had_noresolv".into(), "0".into())]);
        let mut runner = crate::apply::test_support::Scripted::new(vec![]);
        for _ in 0..10 { super::set_openwrt_with(&mut state, "192.0.2.53", &mut runner, |_| panic!("unchanged state must not be saved")).unwrap(); }
        assert!(runner.commands.is_empty());
        state.remove("applied");
        assert!(!super::openwrt_unchanged(&state, "192.0.2.53"));
        let mut retry = crate::apply::test_support::Scripted::new(vec![Ok("".into()), Ok("192.0.2.53".into()), Ok("".into()), Ok("".into())]);
        super::set_openwrt_with(&mut state, "192.0.2.53", &mut retry, |_| Ok(())).unwrap();
        assert_eq!(retry.commands.len(), 4);
        assert!(super::openwrt_unchanged(&state, "192.0.2.53"));
    }

}
