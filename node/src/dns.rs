//! Pluggable DNS backend for full-tunnel exit clients.
//!
//! OpenWrt manages resolver state through UCI/dnsmasq, while generic Linux uses
//! systemd-resolved when available and falls back to direct `/etc/resolv.conf`.

use std::collections::HashMap;
use std::process::{Command, Stdio};

const STATE_PATH: &str = "/run/fluxpeer-dns.state";

pub trait Dns {
    fn name(&self) -> &'static str;
    fn set(&self, dns: &str);
    fn clear(&self);
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
    Command::new("sh")
        .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn cmd_ok(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn cmd_output(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).stderr(Stdio::null()).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

fn uci_get(key: &str) -> Option<String> {
    cmd_output("uci", &["-q", "get", key]).filter(|s| !s.is_empty())
}

fn restart_dnsmasq() {
    let _ = Command::new("/etc/init.d/dnsmasq")
        .arg("restart")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn read_state() -> HashMap<String, String> {
    let mut state = HashMap::new();
    let Ok(raw) = std::fs::read_to_string(STATE_PATH) else {
        return state;
    };
    for line in raw.lines() {
        if let Some((key, value)) = line.split_once('=') {
            state.insert(key.to_string(), value.to_string());
        }
    }
    state
}

fn write_state(state: &HashMap<String, String>) {
    let mut entries: Vec<_> = state.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    let body: String = entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect();
    let _ = std::fs::write(STATE_PATH, body);
}

fn remove_state() {
    let _ = std::fs::remove_file(STATE_PATH);
}

impl Dns for OpenWrtDnsmasq {
    fn name(&self) -> &'static str {
        "openwrt-dnsmasq"
    }

    fn set(&self, dns: &str) {
        let mut state = read_state();
        if !state.contains_key("had_noresolv") {
            if let Some(value) = uci_get("dhcp.@dnsmasq[0].noresolv") {
                state.insert("had_noresolv".to_string(), "1".to_string());
                state.insert("noresolv".to_string(), value);
            } else {
                state.insert("had_noresolv".to_string(), "0".to_string());
            }
        }
        state.insert("dns".to_string(), dns.to_string());
        write_state(&state);

        let _ = cmd_ok("uci", &["set", "dhcp.@dnsmasq[0].noresolv=1"]);
        let servers = uci_get("dhcp.@dnsmasq[0].server").unwrap_or_default();
        if !servers.split_whitespace().any(|server| server == dns) {
            let arg = format!("dhcp.@dnsmasq[0].server={dns}");
            let _ = cmd_ok("uci", &["add_list", &arg]);
        }
        let _ = cmd_ok("uci", &["commit", "dhcp"]);
        restart_dnsmasq();
        tracing::info!(dns, "exit DNS via OpenWrt dnsmasq");
    }

    fn clear(&self) {
        let state = read_state();
        if let Some(dns) = state.get("dns") {
            let arg = format!("dhcp.@dnsmasq[0].server={dns}");
            let _ = cmd_ok("uci", &["del_list", &arg]);
        }
        match state.get("had_noresolv").map(String::as_str) {
            Some("1") => {
                let value = state.get("noresolv").map(String::as_str).unwrap_or("0");
                let arg = format!("dhcp.@dnsmasq[0].noresolv={value}");
                let _ = cmd_ok("uci", &["set", &arg]);
            }
            Some("0") => {
                let _ = cmd_ok("uci", &["delete", "dhcp.@dnsmasq[0].noresolv"]);
            }
            _ => {}
        }
        let _ = cmd_ok("uci", &["commit", "dhcp"]);
        restart_dnsmasq();
        remove_state();
        tracing::info!("exit DNS cleared via OpenWrt dnsmasq");
    }
}

impl Resolvectl {
    fn new(iface: Option<&str>) -> Self {
        Self {
            iface: iface.map(ToString::to_string),
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

    fn set(&self, dns: &str) {
        let iface = self.iface();
        let ok = cmd_ok("resolvectl", &["dns", iface, dns]);
        if ok {
            let _ = cmd_ok("resolvectl", &["domain", iface, "~."]);
            tracing::info!(iface, dns, "exit DNS via resolvectl");
        } else {
            ResolvConf.set(dns);
        }
    }

    fn clear(&self) {
        let iface = self.iface();
        let _ = cmd_ok("resolvectl", &["revert", iface]);
    }
}

impl Dns for ResolvConf {
    fn name(&self) -> &'static str {
        "resolv"
    }

    fn set(&self, dns: &str) {
        let _ = std::fs::write("/etc/resolv.conf", format!("# fluxpeer exit-node\nnameserver {dns}\n"));
        tracing::info!(dns, "exit DNS via /etc/resolv.conf");
    }

    fn clear(&self) {
        tracing::warn!("resolv.conf DNS backend has no saved previous resolver state");
    }
}
