//! Pluggable Linux firewall backend for exit/subnet forwarding.
//!
//! Modern OpenWrt ships nftables without legacy iptables. Keep the existing
//! iptables behavior for generic Linux, but prefer an isolated nft table when
//! available so `down` can delete everything in one operation.

use crate::apply::{self, ApplyError, Result};

pub trait Firewall: Send + Sync {
    fn name(&self) -> &'static str;
    fn up(&self, phys: &str, tun: &str) -> Result;
    fn down(&self, phys: &str, tun: &str) -> Result;
    fn killswitch_on(&self, phys: &str, tun: &str) -> Result;
    fn killswitch_off(&self, phys: &str, tun: &str) -> Result;
}

pub struct Nft;
pub struct Iptables;

pub fn detect() -> Result<Box<dyn Firewall>> {
    match std::env::var("FLUXPEER_FW_BACKEND").ok().as_deref() {
        Some("nft") => return Ok(Box::new(Nft)),
        Some("iptables") => return Ok(Box::new(Iptables)),
        Some(other) if !other.is_empty() => tracing::warn!(backend = other, "unknown FLUXPEER_FW_BACKEND"),
        _ => {}
    }

    let mut nft_error = match apply::output(&["nft", "list", "ruleset"]) {
        Ok(_) => return Ok(Box::new(Nft)),
        Err(e) => e,
    };
    match apply::output(&["iptables", "-S"]) {
        Ok(_) => Ok(Box::new(Iptables)),
        Err(e) => {
            nft_error.stderr.push_str(&format!("; iptables fallback: {e}"));
            Err(nft_error)
        }
    }
}

#[cfg(target_os = "linux")]
const FWD_STATE: &str = "/run/fluxpeer-firewall-forwarding.state";

#[cfg(any(target_os = "linux", test))]
fn sysctl_get_with(runner: &mut impl apply::Runner, key: &str) -> Result<bool> {
    runner.run(&["sysctl", "-n", key], None).map(|s| s.trim() == "1")
}

#[cfg(any(target_os = "linux", test))]
fn sysctl_set_with(runner: &mut impl apply::Runner, key: &str, on: bool) -> Result {
    let result = (|| {
        if sysctl_get_with(runner, key)? == on { return Ok(()); }
        let command = format!("{key}={}", u8::from(on));
        match runner.run(&["sysctl", "-w", &command], None) {
            Ok(_) => Ok(()),
            Err(e) if e.stderr.contains("Read-only file system") && sysctl_get_with(runner, key)? == on => Ok(()),
            Err(e) => Err(e),
        }
    })();
    match result {
        Err(e) if key.starts_with("net.ipv6.") && apply::ipv6_unavailable(&e) => {
            tracing::warn!(%e, "IPv6 forwarding unavailable; continuing IPv4"); Ok(())
        }
        result => result,
    }
}

#[cfg(target_os = "linux")]
fn sysctl_set(key: &str, on: bool) -> Result { sysctl_set_with(&mut apply::System, key, on) }

#[cfg(target_os = "linux")]
static FWD4_WAS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "linux")]
static FWD6_WAS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "linux")]
static FWD_TOUCHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
fn forwarding_up() -> Result {
    use std::sync::atomic::Ordering::Relaxed;
    if !FWD_TOUCHED.load(Relaxed) {
        let v4_was_on = sysctl_get_with(&mut apply::System, "net.ipv4.ip_forward")?;
        let v6_was_on = match sysctl_get_with(&mut apply::System, "net.ipv6.conf.all.forwarding") {
            Ok(on) => on,
            Err(e) if apply::ipv6_unavailable(&e) => { tracing::warn!(%e, "IPv6 forwarding unavailable"); false }
            Err(e) => return Err(e),
        };
        if !std::path::Path::new(FWD_STATE).exists() {
            apply::write(FWD_STATE, format!("v4={}\nv6={}\n", u8::from(v4_was_on), u8::from(v6_was_on)))?;
        }
        FWD4_WAS_ON.store(v4_was_on, Relaxed);
        FWD6_WAS_ON.store(v6_was_on, Relaxed);
        FWD_TOUCHED.store(true, Relaxed);
    }
    sysctl_set("net.ipv4.ip_forward", true)?;
    sysctl_set("net.ipv6.conf.all.forwarding", true)

}

#[cfg(target_os = "linux")]
fn forwarding_down() -> Result {
    use std::sync::atomic::Ordering::Relaxed;
    let remembered = if FWD_TOUCHED.load(Relaxed) {
        Some((FWD4_WAS_ON.load(Relaxed), FWD6_WAS_ON.load(Relaxed)))
    } else {
        read_forwarding_state()?
    };
    let Some((v4_was_on, v6_was_on)) = remembered else { return Ok(()); };
    if !v4_was_on {
        sysctl_set("net.ipv4.ip_forward", false)?;
    }
    if !v6_was_on {
        sysctl_set("net.ipv6.conf.all.forwarding", false)?;
    }
    apply::remove(FWD_STATE)?;
    FWD_TOUCHED.store(false, Relaxed);
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_forwarding_state() -> Result<Option<(bool, bool)>> {
    let s = match std::fs::read_to_string(FWD_STATE) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ApplyError::io(&["read", FWD_STATE], e)),
    };
    let mut v4 = None;
    let mut v6 = None;
    for line in s.lines() {
        if let Some(value) = line.strip_prefix("v4=") {
            v4 = match value { "1" => Some(true), "0" => Some(false), _ => None };
        } else if let Some(value) = line.strip_prefix("v6=") {
            v6 = match value { "1" => Some(true), "0" => Some(false), _ => None };
        }
    }
    match (v4, v6) { (Some(v4), Some(v6)) => Ok(Some((v4, v6))), _ => Err(ApplyError::new(&["read", FWD_STATE], "invalid forwarding state")) }
}

#[cfg(target_os = "linux")]
fn nft(args: &[&str]) -> Result {
    let mut command = vec!["nft"];
    command.extend_from_slice(args);
    apply::run(&command)
}

#[cfg(target_os = "linux")]
fn nft_delete_table() -> Result {
    match nft(&["delete", "table", "inet", "fluxpeer"]) {
        Err(e) if e.exit_code.is_some() && e.missing() => Ok(()),
        result => result,
    }
}

#[cfg(target_os = "linux")]
fn nft_output(args: &[&str]) -> Result<String> {
    let mut command = vec!["nft"];
    command.extend_from_slice(args);
    apply::output(&command)
}

#[cfg(target_os = "linux")]
fn nft_ensure_forward_chain() -> Result {
    nft(&["add", "table", "inet", "fluxpeer"])?;
    nft(&[
        "add", "chain", "inet", "fluxpeer", "forward", "{", "type", "filter", "hook", "forward", "priority", "filter",
        ";", "policy", "accept", ";", "}",
    ])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn nft_forward_has(needles: &[&str]) -> Result<bool> {
    let out = nft_output(&["list", "chain", "inet", "fluxpeer", "forward"])?;
    Ok(out.lines().any(|line| needles.iter().all(|needle| line.contains(needle))))
}

#[cfg(target_os = "linux")]
fn nft_forward_rule_once(rule: &[&str], needles: &[&str]) -> Result {
    if !nft_forward_has(needles)? {
        let mut args = vec!["add", "rule", "inet", "fluxpeer", "forward"];
        args.extend_from_slice(rule);
        nft(&args)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn nft_killswitch_delete(phys: &str, tun: &str) -> Result {
    let out = apply::output(&["nft", "-a", "list", "chain", "inet", "fluxpeer", "forward"])?;
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
            if let ["handle", handle] = pair {
                nft(&["delete", "rule", "inet", "fluxpeer", "forward", "handle", handle])?;
            }
        }
    }
    Ok(())
}

impl Firewall for Nft {
    fn name(&self) -> &'static str {
        "nft"
    }

    fn up(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            forwarding_up()?;
            // Rebuild our own table from scratch. This keeps `up` idempotent and
            // keeps all fluxpeer-owned rules removable by one delete-table.
            nft_delete_table()?;
            nft(&["add", "table", "inet", "fluxpeer"])?;
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
            ])?;
            nft(&[
                "add", "chain", "inet", "fluxpeer", "forward", "{", "type", "filter", "hook", "forward", "priority",
                "filter", ";", "policy", "accept", ";", "}",
            ])?;
            nft(&[
                "add",
                "rule",
                "inet",
                "fluxpeer",
                "postrouting",
                "oifname",
                phys,
                "masquerade",
            ])?;
            nft(&["add", "rule", "inet", "fluxpeer", "forward", "iifname", tun, "accept"])?;
            nft(&["add", "rule", "inet", "fluxpeer", "forward", "oifname", tun, "accept"])?;
            tracing::info!(phys, tun, "firewall nft up");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }

    fn down(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            let _ = (phys, tun);
            nft_delete_table()?;
            forwarding_down()?;
            tracing::info!("firewall nft down");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }

    fn killswitch_on(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            nft_ensure_forward_chain()?;
            nft_forward_rule_once(&["iifname", tun, "accept"], &["iifname", tun, "accept"])?;
            nft_forward_rule_once(&["oifname", tun, "accept"], &["oifname", tun, "accept"])?;
            nft_killswitch_delete(phys, tun)?;
            nft(&[
                "add", "rule", "inet", "fluxpeer", "forward", "oifname", phys, "iifname", "!=", tun, "drop",
            ])?;
            tracing::info!(phys, tun, "firewall nft killswitch on");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }

    fn killswitch_off(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            nft_killswitch_delete(phys, tun)?;
            tracing::info!(phys, tun, "firewall nft killswitch off");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }
}

#[cfg(target_os = "linux")]
const IPT_BINS: [&str; 2] = ["iptables", "ip6tables"];

#[cfg(any(target_os = "linux", test))]
fn absent_table_or_chain(error: &ApplyError) -> bool {
    error.stderr.contains("Table does not exist") || error.stderr.contains("table does not exist")
        || error.stderr.contains("No chain/target/match") || error.stderr.contains("No such rule") || error.missing()
}

#[cfg(any(target_os = "linux", test))]
fn optional_iptables6(bin: &str, error: &ApplyError) -> bool {
    bin == "ip6tables" && (apply::ipv6_unavailable(error) || error.exit_code == Some(3) || absent_table_or_chain(error))
}

#[cfg(any(target_os = "linux", test))]
fn iptables_ensure_with(runner: &mut impl apply::Runner, bin: &str, table: &[&str], add_op: &str, rule: &[&str]) -> Result {
    let command = |op| { let mut c = vec![bin]; c.extend_from_slice(table); c.push(op); c.extend_from_slice(rule); c };
    let result = match runner.run(&command("-C"), None) {
        Ok(_) => Ok(()),
        Err(e) if e.exit_code == Some(1) && !absent_table_or_chain(&e) => runner.run(&command(add_op), None).map(|_| ()),
        Err(e) => Err(e),
    };
    match result {
        Err(e) if optional_iptables6(bin, &e) => { tracing::warn!(%e, "IPv6 firewall unavailable; continuing IPv4"); Ok(()) }
        result => result,
    }
}

#[cfg(target_os = "linux")]
fn iptables_ensure(bin: &str, table: &[&str], add_op: &str, rule: &[&str]) -> Result {
    iptables_ensure_with(&mut apply::System, bin, table, add_op, rule)
}

#[cfg(any(target_os = "linux", test))]
fn iptables_drain_with(runner: &mut impl apply::Runner, bin: &str, table: &[&str], rule: &[&str]) -> Result {
    for _ in 0..256 {
        let mut c = vec![bin]; c.extend_from_slice(table); c.push("-C"); c.extend_from_slice(rule);
        match runner.run(&c, None) {
            Err(e) if e.exit_code == Some(1) || (e.exit_code.is_some() && absent_table_or_chain(&e)) || optional_iptables6(bin, &e) => return Ok(()),
            result => { result?; }
        }
        let mut c = vec![bin]; c.extend_from_slice(table); c.push("-D"); c.extend_from_slice(rule);
        match runner.run(&c, None) {
            Err(e) if (e.exit_code.is_some() && absent_table_or_chain(&e)) || optional_iptables6(bin, &e) => return Ok(()),
            result => { result?; }
        }
    }
    Err(ApplyError::new(&[bin, "-D"], "rule removal limit reached"))
}

#[cfg(target_os = "linux")]
fn iptables_drain(bin: &str, table: &[&str], rule: &[&str]) -> Result {
    iptables_drain_with(&mut apply::System, bin, table, rule)
}

impl Firewall for Iptables {
    fn name(&self) -> &'static str {
        "iptables"
    }

    fn up(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            forwarding_up()?;
            for ipt in IPT_BINS {
                iptables_ensure(
                    ipt,
                    &["-t", "nat"],
                    "-A",
                    &["POSTROUTING", "-o", phys, "-j", "MASQUERADE"],
                )?;
                iptables_ensure(ipt, &[], "-I", &["FORWARD", "-i", tun, "-j", "ACCEPT"])?;
                iptables_ensure(ipt, &[], "-I", &["FORWARD", "-o", tun, "-j", "ACCEPT"])?;
            }
            tracing::info!(phys, tun, "firewall iptables up");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }

    fn down(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            for ipt in IPT_BINS {
                iptables_drain(ipt, &["-t", "nat"], &["POSTROUTING", "-o", phys, "-j", "MASQUERADE"])?;
                iptables_drain(ipt, &[], &["FORWARD", "-i", tun, "-j", "ACCEPT"])?;
                iptables_drain(ipt, &[], &["FORWARD", "-o", tun, "-j", "ACCEPT"])?;
            }
            forwarding_down()?;
            tracing::info!(phys, tun, "firewall iptables down");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }

    fn killswitch_on(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            for ipt in IPT_BINS {
                iptables_ensure(ipt, &[], "-A", &["FORWARD", "-o", phys, "!", "-i", tun, "-j", "DROP"])?;
            }
            tracing::info!(phys, tun, "firewall iptables killswitch on");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }

    fn killswitch_off(&self, phys: &str, tun: &str) -> Result {
        #[cfg(target_os = "linux")]
        {
            for ipt in IPT_BINS {
                iptables_drain(ipt, &[], &["FORWARD", "-o", phys, "!", "-i", tun, "-j", "DROP"])?;
            }
            tracing::info!(phys, tun, "firewall iptables killswitch off");
        }
        #[cfg(not(target_os = "linux"))]
        { Err(ApplyError::new(&[self.name(), phys, tun], "Linux firewall backend is unavailable on this platform")) }
        #[cfg(target_os = "linux")]
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apply::test_support::{Scripted, error};

    #[test]
    fn sysctl_skips_unchanged_readonly_values_and_optional_missing_ipv6() {
        let mut runner = Scripted::new(vec![Ok("1\n".into())]);
        sysctl_set_with(&mut runner, "net.ipv4.ip_forward", true).unwrap();
        assert_eq!(runner.commands, [vec!["sysctl", "-n", "net.ipv4.ip_forward"]]);
        let mut runner = Scripted::new(vec![Err(error(None, "No such file or directory"))]);
        sysctl_set_with(&mut runner, "net.ipv6.conf.all.forwarding", true).unwrap();
        assert_eq!(runner.commands, [vec!["sysctl", "-n", "net.ipv6.conf.all.forwarding"]]);
        let mut runner = Scripted::new(vec![Ok("0".into()), Err(error(Some(1), "Read-only file system")), Ok("1".into())]);
        sysctl_set_with(&mut runner, "net.ipv6.conf.all.forwarding", true).unwrap();
        assert_eq!(runner.commands[1], ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"]);
        let mut runner = Scripted::new(vec![Ok("0".into()), Err(error(Some(1), "Read-only file system")), Ok("0".into())]);
        assert!(sysctl_set_with(&mut runner, "net.ipv6.conf.all.forwarding", true).is_err());
    }

    #[test]
    fn iptables_ipv6_absence_is_optional_but_ipv4_and_permission_errors_are_not() {
        let rule = ["POSTROUTING", "-o", "wan0", "-j", "MASQUERADE"];
        for failure in [error(None, "missing executable"), error(Some(3), "Table does not exist"), error(Some(1), "No chain/target/match by that name.")] {
            let mut runner = Scripted::new(vec![Err(failure)]);
            iptables_ensure_with(&mut runner, "ip6tables", &["-t", "nat"], "-A", &rule).unwrap();
            assert_eq!(runner.commands, [vec!["ip6tables", "-t", "nat", "-C", "POSTROUTING", "-o", "wan0", "-j", "MASQUERADE"]]);
        }
        let mut runner = Scripted::new(vec![Err(error(Some(1), "Bad rule")), Ok("".into())]);
        iptables_ensure_with(&mut runner, "iptables", &["-t", "nat"], "-A", &rule).unwrap();
        assert_eq!(runner.commands[1], ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "wan0", "-j", "MASQUERADE"]);
        for bin in ["iptables", "ip6tables"] {
            let mut runner = Scripted::new(vec![Err(error(Some(4), "Permission denied"))]);
            assert_eq!(iptables_ensure_with(&mut runner, bin, &[], "-A", &rule).unwrap_err().exit_code, Some(4));
        }
        let mut runner = Scripted::new(vec![Err(error(Some(3), "Table does not exist"))]);
        assert!(iptables_ensure_with(&mut runner, "iptables", &[], "-A", &rule).is_err());
    }

    #[test]
    fn drain_accepts_absent_rules_tables_and_chains_and_propagates_other_failures() {
        for failure in [error(Some(1), "Bad rule"), error(Some(3), "Table does not exist"), error(Some(1), "No chain/target/match by that name.")] {
            let mut runner = Scripted::new(vec![Err(failure)]);
            iptables_drain_with(&mut runner, "iptables", &["-t", "nat"], &["POSTROUTING"]).unwrap();
            assert_eq!(runner.commands[0], ["iptables", "-t", "nat", "-C", "POSTROUTING"]);
        }
        let mut runner = Scripted::new(vec![Ok("".into()), Ok("".into()), Err(error(Some(1), "Bad rule"))]);
        iptables_drain_with(&mut runner, "iptables", &[], &["FORWARD"]).unwrap();
        assert_eq!(runner.commands[1], ["iptables", "-D", "FORWARD"]);
        let mut runner = Scripted::new(vec![Ok("".into()), Err(error(Some(4), "Permission denied"))]);
        assert!(iptables_drain_with(&mut runner, "iptables", &[], &["FORWARD"]).is_err());
    }
}
