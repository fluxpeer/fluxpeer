//! Pluggable Linux firewall backend for exit/subnet forwarding.
//!
//! Modern OpenWrt ships nftables without legacy iptables. Keep the existing
//! iptables behavior for generic Linux, but prefer an isolated nft table when
//! available so `down` can delete everything in one operation.

use std::process::{Command, Stdio};

pub trait Firewall {
    fn name(&self) -> &'static str;
    fn up(&self, phys: &str, tun: &str);
    fn down(&self, phys: &str, tun: &str);
    fn killswitch_on(&self, phys: &str, tun: &str);
    fn killswitch_off(&self, phys: &str, tun: &str);
}

pub struct Nft;
pub struct Iptables;
struct Noop;

pub fn detect() -> Box<dyn Firewall> {
    match std::env::var("FLUXPEER_FW_BACKEND").ok().as_deref() {
        Some("nft") => return Box::new(Nft),
        Some("iptables") => return Box::new(Iptables),
        Some(other) if !other.is_empty() => tracing::warn!(backend = other, "unknown FLUXPEER_FW_BACKEND"),
        _ => {}
    }

    if nft_probe() {
        return Box::new(Nft);
    }
    if cmd_ok("iptables", &["-S"]) {
        return Box::new(Iptables);
    }
    tracing::warn!("no usable firewall backend found (nft/iptables unavailable)");
    Box::new(Noop)
}

fn nft_probe() -> bool {
    if !cmd_ok("nft", &["add", "table", "inet", "fluxpeer-probe"]) {
        return false;
    }
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "fluxpeer-probe"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    true
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

#[cfg(target_os = "linux")]
const FWD4: &str = "/proc/sys/net/ipv4/ip_forward";
#[cfg(target_os = "linux")]
const FWD6: &str = "/proc/sys/net/ipv6/conf/all/forwarding";
#[cfg(target_os = "linux")]
const FWD_STATE: &str = "/run/fluxpeer-firewall-forwarding.state";

#[cfg(target_os = "linux")]
fn sysctl_is_on(path: &str) -> bool {
    std::fs::read_to_string(path).map(|s| s.trim() == "1").unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn sysctl_set(key: &str, on: bool) {
    let value = if on { "1" } else { "0" };
    let _ = Command::new("sysctl")
        .args(["-w", &format!("{key}={value}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(target_os = "linux")]
static FWD4_WAS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "linux")]
static FWD6_WAS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "linux")]
static FWD_TOUCHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
fn forwarding_up() {
    use std::sync::atomic::Ordering::Relaxed;
    let v4_was_on = sysctl_is_on(FWD4);
    let v6_was_on = sysctl_is_on(FWD6);
    FWD4_WAS_ON.store(v4_was_on, Relaxed);
    FWD6_WAS_ON.store(v6_was_on, Relaxed);
    FWD_TOUCHED.store(true, Relaxed);
    if !std::path::Path::new(FWD_STATE).exists() {
        let _ = std::fs::write(
            FWD_STATE,
            format!("v4={}\nv6={}\n", u8::from(v4_was_on), u8::from(v6_was_on)),
        );
    }
    sysctl_set("net.ipv4.ip_forward", true);
    sysctl_set("net.ipv6.conf.all.forwarding", true);
}

#[cfg(target_os = "linux")]
fn forwarding_down() {
    use std::sync::atomic::Ordering::Relaxed;
    let remembered = if FWD_TOUCHED.load(Relaxed) {
        Some((FWD4_WAS_ON.load(Relaxed), FWD6_WAS_ON.load(Relaxed)))
    } else {
        read_forwarding_state()
    };
    let Some((v4_was_on, v6_was_on)) = remembered else {
        return;
    };
    if !v4_was_on {
        sysctl_set("net.ipv4.ip_forward", false);
    }
    if !v6_was_on {
        sysctl_set("net.ipv6.conf.all.forwarding", false);
    }
    let _ = std::fs::remove_file(FWD_STATE);
}

#[cfg(target_os = "linux")]
fn read_forwarding_state() -> Option<(bool, bool)> {
    let s = std::fs::read_to_string(FWD_STATE).ok()?;
    let mut v4 = None;
    let mut v6 = None;
    for line in s.lines() {
        if let Some(value) = line.strip_prefix("v4=") {
            v4 = Some(value == "1");
        } else if let Some(value) = line.strip_prefix("v6=") {
            v6 = Some(value == "1");
        }
    }
    Some((v4?, v6?))
}

#[cfg(target_os = "linux")]
fn nft(args: &[&str]) {
    let _ = Command::new("nft")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(target_os = "linux")]
fn nft_output(args: &[&str]) -> Option<String> {
    let out = Command::new("nft").args(args).stderr(Stdio::null()).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn nft_ensure_forward_chain() {
    nft(&["add", "table", "inet", "fluxpeer"]);
    nft(&[
        "add", "chain", "inet", "fluxpeer", "forward", "{", "type", "filter", "hook", "forward", "priority", "filter",
        ";", "policy", "accept", ";", "}",
    ]);
}

#[cfg(target_os = "linux")]
fn nft_forward_has(needles: &[&str]) -> bool {
    let Some(out) = nft_output(&["list", "chain", "inet", "fluxpeer", "forward"]) else {
        return false;
    };
    out.lines()
        .any(|line| needles.iter().all(|needle| line.contains(needle)))
}

#[cfg(target_os = "linux")]
fn nft_forward_rule_once(rule: &[&str], needles: &[&str]) {
    if !nft_forward_has(needles) {
        let mut args = vec!["add", "rule", "inet", "fluxpeer", "forward"];
        args.extend_from_slice(rule);
        nft(&args);
    }
}

#[cfg(target_os = "linux")]
fn nft_killswitch_delete(phys: &str, tun: &str) {
    let Some(out) = nft_output(&["-a", "list", "chain", "inet", "fluxpeer", "forward"]) else {
        return;
    };
    for line in out.lines() {
        if !(line.contains("drop")
            && line.contains("oifname")
            && line.contains(phys)
            && line.contains("iifname")
            && line.contains(tun))
        {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        for pair in parts.windows(2) {
            if pair[0] == "handle" {
                nft(&["delete", "rule", "inet", "fluxpeer", "forward", "handle", pair[1]]);
            }
        }
    }
}

impl Firewall for Nft {
    fn name(&self) -> &'static str {
        "nft"
    }

    fn up(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            forwarding_up();
            // Rebuild our own table from scratch. This keeps `up` idempotent and
            // keeps all fluxpeer-owned rules removable by one delete-table.
            nft(&["delete", "table", "inet", "fluxpeer"]);
            nft(&["add", "table", "inet", "fluxpeer"]);
            nft(&[
                "add",
                "chain",
                "inet",
                "fluxpeer",
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "srcnat",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ]);
            nft(&[
                "add", "chain", "inet", "fluxpeer", "forward", "{", "type", "filter", "hook", "forward", "priority",
                "filter", ";", "policy", "accept", ";", "}",
            ]);
            nft(&[
                "add",
                "rule",
                "inet",
                "fluxpeer",
                "postrouting",
                "oifname",
                phys,
                "masquerade",
            ]);
            nft(&["add", "rule", "inet", "fluxpeer", "forward", "iifname", tun, "accept"]);
            nft(&["add", "rule", "inet", "fluxpeer", "forward", "oifname", tun, "accept"]);
            tracing::info!(phys, tun, "firewall nft up");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }

    fn down(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            let _ = (phys, tun);
            nft(&["delete", "table", "inet", "fluxpeer"]);
            forwarding_down();
            tracing::info!("firewall nft down");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }

    fn killswitch_on(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            nft_ensure_forward_chain();
            nft_forward_rule_once(&["iifname", tun, "accept"], &["iifname", tun, "accept"]);
            nft_forward_rule_once(&["oifname", tun, "accept"], &["oifname", tun, "accept"]);
            nft_killswitch_delete(phys, tun);
            nft(&[
                "add", "rule", "inet", "fluxpeer", "forward", "oifname", phys, "iifname", "!=", tun, "drop",
            ]);
            tracing::info!(phys, tun, "firewall nft killswitch on");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }

    fn killswitch_off(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            nft_killswitch_delete(phys, tun);
            tracing::info!(phys, tun, "firewall nft killswitch off");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }
}

#[cfg(target_os = "linux")]
const IPT_BINS: [&str; 2] = ["iptables", "ip6tables"];

#[cfg(target_os = "linux")]
fn iptables_ensure(bin: &str, table: &[&str], add_op: &str, rule: &[&str]) {
    let run = |op: &str| {
        let mut a: Vec<&str> = table.to_vec();
        a.push(op);
        a.extend_from_slice(rule);
        Command::new(bin)
            .args(&a)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !run("-C") {
        let _ = run(add_op);
    }
}

#[cfg(target_os = "linux")]
fn iptables_drain(bin: &str, table: &[&str], rule: &[&str]) {
    for _ in 0..256 {
        let mut a: Vec<&str> = table.to_vec();
        a.push("-D");
        a.extend_from_slice(rule);
        let removed = Command::new(bin)
            .args(&a)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !removed {
            break;
        }
    }
}

impl Firewall for Iptables {
    fn name(&self) -> &'static str {
        "iptables"
    }

    fn up(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            forwarding_up();
            for ipt in IPT_BINS {
                iptables_ensure(
                    ipt,
                    &["-t", "nat"],
                    "-A",
                    &["POSTROUTING", "-o", phys, "-j", "MASQUERADE"],
                );
                iptables_ensure(ipt, &[], "-I", &["FORWARD", "-i", tun, "-j", "ACCEPT"]);
                iptables_ensure(ipt, &[], "-I", &["FORWARD", "-o", tun, "-j", "ACCEPT"]);
            }
            tracing::info!(phys, tun, "firewall iptables up");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }

    fn down(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            for ipt in IPT_BINS {
                iptables_drain(ipt, &["-t", "nat"], &["POSTROUTING", "-o", phys, "-j", "MASQUERADE"]);
                iptables_drain(ipt, &[], &["FORWARD", "-i", tun, "-j", "ACCEPT"]);
                iptables_drain(ipt, &[], &["FORWARD", "-o", tun, "-j", "ACCEPT"]);
            }
            forwarding_down();
            tracing::info!(phys, tun, "firewall iptables down");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }

    fn killswitch_on(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            for ipt in IPT_BINS {
                iptables_ensure(ipt, &[], "-A", &["FORWARD", "-o", phys, "!", "-i", tun, "-j", "DROP"]);
            }
            tracing::info!(phys, tun, "firewall iptables killswitch on");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }

    fn killswitch_off(&self, phys: &str, tun: &str) {
        #[cfg(target_os = "linux")]
        {
            for ipt in IPT_BINS {
                iptables_drain(ipt, &[], &["FORWARD", "-o", phys, "!", "-i", tun, "-j", "DROP"]);
            }
            tracing::info!(phys, tun, "firewall iptables killswitch off");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (phys, tun);
    }
}

impl Firewall for Noop {
    fn name(&self) -> &'static str {
        "none"
    }

    fn up(&self, phys: &str, tun: &str) {
        let _ = (phys, tun);
        tracing::warn!("firewall noop up");
    }

    fn down(&self, phys: &str, tun: &str) {
        let _ = (phys, tun);
        tracing::warn!("firewall noop down");
    }

    fn killswitch_on(&self, phys: &str, tun: &str) {
        let _ = (phys, tun);
        tracing::warn!("firewall noop killswitch on");
    }

    fn killswitch_off(&self, phys: &str, tun: &str) {
        let _ = (phys, tun);
        tracing::warn!("firewall noop killswitch off");
    }
}
