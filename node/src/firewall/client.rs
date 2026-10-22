// SPDX-License-Identifier: BSD-3-Clause
//! Persistent client OUTPUT protection. No Drop implementation removes rules.
use crate::apply::{ApplyError, Result};
#[cfg(any(target_os = "linux", test))]
use crate::apply;
use std::time::{Duration, Instant};
use std::path::Path;

#[cfg(target_os = "linux")]
const ROOT: &str = "/run/fluxpeer-firewall";
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) fn requested(enabled: bool, use_exit: Option<&str>) -> bool {
    enabled && use_exit.is_some_and(|mode| !mode.trim().is_empty() && mode.trim() != "off")
}
pub(crate) fn validate_config(cfg: &serde_json::Value) -> std::io::Result<bool> {
    let enabled = match cfg.get("kill_switch") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "kill_switch must be a boolean"))?,
    };
    let mode = match cfg.get("use_exit") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(crate::daemon::normalize_use_exit(value.as_str().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "use_exit must be a string"))?)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?),
    };
    let active = requested(enabled, mode.as_deref());
    supported(active)?;
    Ok(active)
}
pub(crate) fn supported(active: bool) -> std::io::Result<()> {
    if active && !cfg!(target_os = "linux") {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "client kill-switch is unsupported on this platform; macOS pf support is pending T-0042"));
    }
    Ok(())
}
#[derive(Default)]
pub(crate) struct Guard {
    last_check: Option<Instant>, desired: Vec<String>, attempted: Vec<String>, error: Option<ApplyError>,
}
impl Guard {
    pub fn sync(&mut self, tun: &str, addresses: &[String], retain: bool) -> Result {
        self.sync_using(addresses, retain, Instant::now(), |addresses, retain| sync_system(tun, addresses, retain))
    }
    fn sync_using(&mut self, addresses: &[String], retain: bool, now: Instant,
        install: impl FnOnce(&[String], bool) -> Result<Vec<String>>) -> Result {
        let mut desired = addresses.to_vec();
        if retain { desired.extend(self.desired.iter().cloned()); }
        desired.sort(); desired.dedup();
        if self.attempted == desired && !due(self.last_check, now) {
            return self.error.clone().map_or(Ok(()), Err);
        }
        self.attempted = desired; self.last_check = Some(now);
        match install(addresses, retain) {
            Ok(applied) => { self.desired = applied; self.attempted = self.desired.clone(); self.error = None; Ok(()) },
            Err(error) => { self.error = Some(error.clone()); Err(error) },
        }
    }
    pub fn check(&mut self, tun: &str) -> Result {
        self.sync(tun, &self.attempted.clone(), true)
    }
}
fn due(last: Option<Instant>, now: Instant) -> bool { last.is_none_or(|last| now.saturating_duration_since(last) >= CHECK_INTERVAL) }

fn sync_system(tun: &str, addresses: &[String], retain: bool) -> Result<Vec<String>> {
    #[cfg(target_os = "linux")]
    { sync_with(&mut apply::System, Path::new(ROOT), tun, addresses, retain, std::env::var("FLUXPEER_FW_BACKEND").ok().as_deref()) }
    #[cfg(not(target_os = "linux"))]
    { let _ = (tun, addresses, retain); Err(ApplyError::io(&["kill-switch"], std::io::Error::new(std::io::ErrorKind::Unsupported, "client kill-switch unavailable"))) }
}
pub(crate) fn clear(tun: &str) -> Result {
    #[cfg(target_os = "linux")]
    {
        clear_with(&mut apply::System, Path::new(ROOT), tun)
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = tun; Ok(()) }
}

pub(crate) fn retained(tun: &str) -> Result<bool> {
    #[cfg(target_os = "linux")]
    { load(Path::new(ROOT), tun).map(|plan| plan.is_some()) }
    #[cfg(not(target_os = "linux"))]
    { let _ = tun; Ok(false) }
}
/// A host OUTPUT policy cannot be shared by different memberships. Even a
/// stopped engine's journal reserves protection until explicit down/disable.
pub(crate) fn exclusive_error(iface: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::WouldBlock, format!("kill-switch active on {iface}; disable it first"))
}
pub(crate) fn ensure_exclusive_at(root: &Path, iface: &str) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()), result => result?,
    };
    #[derive(serde::Deserialize)]
    struct Owner { tun: String }
    for entry in entries {
        let path = entry?.path();
        if !path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.ends_with(".output.json")) { continue; }
        let Some(bytes) = crate::carriers::read_private(&path)? else { continue; };
        let owner: Owner = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
        if !crate::daemon::valid_iface(&owner.tun)
            || path.file_name().and_then(|name| name.to_str()) != Some(format!("fluxpeer_{}.output.json", hex::encode(&owner.tun)).as_str()) {
            return Err(std::io::Error::other("invalid kill-switch journal identity"));
        }
        if owner.tun != iface { return Err(exclusive_error(&owner.tun)); }
    }
    Ok(())
}

/// A daemon keeps retained guards healthy even after their member engine exits.
pub(crate) fn repair_all() -> Result {
    #[cfg(target_os = "linux")]
    {
        let root = Path::new(ROOT);
        if !root.exists() { return Ok(()); }
        let mut results = Vec::new();
        for item in std::fs::read_dir(root)? {
            let path = item?.path();
            if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".output.json")) {
                let Some(bytes) = crate::carriers::read_private(&path)? else { continue; };
                let plan: Plan = serde_json::from_slice(&bytes).map_err(|e| ApplyError::new(&["kill-switch", "read"], e.to_string()))?;
                results.push(repair_with(&mut apply::System, root, &plan.tun));
            }
        }
        apply::all(results)
    }
    #[cfg(not(target_os = "linux"))]
    { Ok(()) }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
struct Plan { tun: String, backend: String, addresses: Vec<String> }
#[cfg(any(target_os = "linux", test))]
impl Plan {
    fn new(tun: &str, backend: &str, addresses: &[String]) -> Result<Self> {
        super::instance(tun)?;
        if !matches!(backend, "nft" | "iptables") { return Err(ApplyError::new(&["kill-switch"], "invalid backend")); }
        let mut addresses = addresses.iter().map(|address| address.parse::<std::net::IpAddr>()
            .map(|address| address.to_string()).map_err(|e| ApplyError::new(&["kill-switch", "bypass"], e.to_string())))
            .collect::<Result<Vec<_>>>()?;
        addresses.sort(); addresses.dedup();
        Ok(Self { tun: tun.into(), backend: backend.into(), addresses })
    }
    fn table(&self) -> Result<String> { Ok(format!("{}_output", super::instance(&self.tun)?)) }
    fn chain(&self) -> String { format!("FPO_{}", self.tun) }
    fn tag(&self) -> Result<String> {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        self.tun.hash(&mut hash); self.addresses.hash(&mut hash);
        Ok(format!("{}:{:016x}", self.table()?, hash.finish()))
    }
}
#[cfg(any(target_os = "linux", test))]
fn state_path(root: &Path, tun: &str) -> Result<std::path::PathBuf> { Ok(root.join(format!("{}.output.json", super::instance(tun)?))) }
#[cfg(any(target_os = "linux", test))]
fn load(root: &Path, tun: &str) -> Result<Option<Plan>> {
    match crate::carriers::read_private(&state_path(root, tun)?) {
        Ok(Some(data)) => {
            let plan: Plan = serde_json::from_slice(&data).map_err(|e| ApplyError::new(&["kill-switch", "read"], e.to_string()))?;
            if plan.tun != tun { return Err(ApplyError::new(&["kill-switch", "read"], "identity mismatch")); }
            Plan::new(tun, &plan.backend, &plan.addresses).map(Some)
        },
        Ok(None) => Ok(None),
        Err(error) => Err(error.into()),
    }
}
#[cfg(any(target_os = "linux", test))]
fn save(root: &Path, plan: &Plan) -> Result {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    let bytes = serde_json::to_vec(plan).map_err(|e| ApplyError::new(&["kill-switch", "save"], e.to_string()))?;
    file.write_all(&bytes)?; file.as_file().sync_all()?;
    file.persist(state_path(root, &plan.tun)?).map_err(|e| ApplyError::from(e.error))?;
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn sync_with(runner: &mut impl apply::Runner, root: &Path, tun: &str, addresses: &[String], retain: bool, backend: Option<&str>) -> Result<Vec<String>> {
    let _lock = super::forwarding::State::lock(root)?;
    let previous = load(root, tun)?;
    let backend = match &previous { Some(plan) => plan.backend.clone(), None => super::detect_with(runner, backend)?.name().into() };
    let mut addresses = addresses.to_vec();
    if retain && let Some(old) = &previous { addresses.extend(old.addresses.iter().cloned()); }
    let plan = Plan::new(tun, &backend, &addresses)?;
    // Keep a durable removal/repair obligation before the first host mutation.
    save(root, &plan)?;
    if previous.as_ref() != Some(&plan) { install(runner, &plan)?; }
    else if !healthy(runner, &plan)? {
        tracing::warn!(%tun, "client kill-switch rules missing or displaced; restoring retained policy");
        install(runner, &plan)?;
    }
    Ok(plan.addresses)
}
#[cfg(any(target_os = "linux", test))]
fn repair_with(runner: &mut impl apply::Runner, root: &Path, tun: &str) -> Result {
    if !state_path(root, tun)?.exists() { return Ok(()); }
    let _lock = super::forwarding::State::lock(root)?;
    if let Some(plan) = load(root, tun)? && !healthy(runner, &plan)? {
        tracing::warn!(%tun, "client kill-switch rules missing or displaced; restoring retained policy");
        install(runner, &plan)?;
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn clear_with(runner: &mut impl apply::Runner, root: &Path, tun: &str) -> Result {
    if !state_path(root, tun)?.exists() { crate::carriers::remove_at(root, tun)?; return Ok(()); }
    let _lock = super::forwarding::State::lock(root)?;
    if let Some(plan) = load(root, tun)? {
        if plan.backend == "nft" {
            match runner.run(&["nft", "delete", "table", "inet", &plan.table()?], None) {
                Err(e) if missing(&e) => {}, result => { result?; },
            }
        } else {
            for bin in ["iptables", "ip6tables"] {
                let chain = plan.chain();
                super::iptables_drain_with(runner, bin, &[], &["OUTPUT", "-j", &chain])?;
                match super::iptables_run(runner, &[bin, "-S", &chain]) {
                    Err(e) if missing(&e) => continue, result => { result?; },
                }
                super::iptables_run(runner, &[bin, "-F", &chain])?;
                super::iptables_run(runner, &[bin, "-X", &chain])?;
            }
        }
        crate::carriers::remove_at(root, tun)?;
        std::fs::remove_file(state_path(root, tun)?)?;
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn missing(error: &ApplyError) -> bool { !super::permission_denied(error) && error.exit_code.is_some() && super::absent_table_or_chain(error) }

#[cfg(any(target_os = "linux", test))]
fn nft_rules(plan: &Plan) -> Vec<String> {
    let mut rules = vec!["oifname \"lo\" accept".into(), format!("oifname \"{}\" accept", plan.tun),
        "ip daddr 169.254.0.0/16 accept".into(), "ip6 daddr fe80::/10 accept".into(),
        "udp sport 68 udp dport 67 accept".into(), "udp sport 546 udp dport 547 accept".into(),
        "ip6 daddr ff02::/16 icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept".into()];
    rules.extend(plan.addresses.iter().map(|ip| format!("{} daddr {ip} accept", if ip.contains(':') { "ip6" } else { "ip" })));
    rules
}
#[cfg(any(target_os = "linux", test))]
fn ipt_rules(plan: &Plan, v6: bool) -> Vec<String> {
    let mut rules = vec!["-o lo -j RETURN".into(), format!("-o {} -j RETURN", plan.tun)];
    if v6 {
        rules.push("-d fe80::/10 -j RETURN".into());
        rules.push("-p udp --sport 546 --dport 547 -j RETURN".into());
        for kind in [133, 135, 136] { rules.push(format!("-d ff02::/16 -p ipv6-icmp --icmpv6-type {kind} -j RETURN")); }
    } else {
        rules.push("-d 169.254.0.0/16 -j RETURN".into());
        rules.push("-p udp --sport 68 --dport 67 -j RETURN".into());
    }
    rules.extend(plan.addresses.iter().filter(|ip| ip.contains(':') == v6).map(|ip| format!("-d {ip} -j RETURN")));
    rules.push("-j DROP".into()); rules
}
#[cfg(any(target_os = "linux", test))]
fn install(runner: &mut impl apply::Runner, plan: &Plan) -> Result {
    let tag = plan.tag()?;
    if plan.backend == "nft" {
        let table = plan.table()?;
        let rules = nft_rules(plan).iter().enumerate().map(|(i, rule)| format!("{rule} comment \"{tag}:{i}\";\n")).collect::<String>();
        let script = format!("add table inet {table}\ndelete table inet {table}\ntable inet {table} {{ chain output {{ type filter hook output priority -150; policy drop;\n{rules}}} }}\n");
        runner.run(&["nft", "-f", "-"], Some(&script))?;
    } else {
        let chain = plan.chain();
        for (bin, restore, v6) in [("iptables", "iptables-restore", false), ("ip6tables", "ip6tables-restore", true)] {
            let rules = ipt_rules(plan, v6).iter().enumerate().map(|(i, rule)| format!("-A {chain} -m comment --comment {tag}:{i} {rule}\n")).collect::<String>();
            runner.run(&[restore, "--wait", "10", "--noflush"], Some(&format!("*filter\n:{chain} - [0:0]\n-F {chain}\n{rules}COMMIT\n")))?;
            // Insert before Docker/external OUTPUT jumps. Keeping an older
            // duplicate attached avoids a transient unprotected delete/add gap.
            if !hook_first(runner, bin, &chain)? { super::iptables_run(runner, &[bin, "-I", "OUTPUT", "1", "-j", &chain])?; }
        }
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn hook_first(runner: &mut impl apply::Runner, bin: &str, chain: &str) -> Result<bool> {
    let rules = super::iptables_run(runner, &[bin, "-S", "OUTPUT"])?;
    // Several local memberships can each guard OUTPUT. They must all precede
    // external jumps without continually displacing/duplicating one another.
    Ok(rules.lines().filter(|line| line.starts_with("-A "))
        .take_while(|line| line.starts_with("-A OUTPUT -j FPO_"))
        .any(|line| line == format!("-A OUTPUT -j {chain}")))
}
#[cfg(any(target_os = "linux", test))]
fn healthy(runner: &mut impl apply::Runner, plan: &Plan) -> Result<bool> {
    let tag = plan.tag()?;
    if plan.backend == "nft" {
        let raw = match runner.run(&["nft", "-j", "list", "table", "inet", &plan.table()?], None) {
            Err(e) if missing(&e) => return Ok(false), result => result?,
        };
        let json: serde_json::Value = serde_json::from_str(&raw).map_err(|e| ApplyError::new(&["kill-switch", "inspect"], e.to_string()))?;
        let items = json["nftables"].as_array().ok_or_else(|| ApplyError::new(&["kill-switch", "inspect"], "missing nftables array"))?;
        let chain = items.iter().filter_map(|v| v.get("chain")).any(|c| c["name"] == "output" && c["hook"] == "output" && c["policy"] == "drop");
        let comments: Vec<_> = items.iter().filter_map(|v| v.pointer("/rule/comment").and_then(|c| c.as_str())).collect();
        Ok(chain && comments.len() == nft_rules(plan).len() && (0..comments.len()).all(|i| comments.contains(&format!("{tag}:{i}").as_str())))
    } else {
        for (bin, v6) in [("iptables", false), ("ip6tables", true)] {
            let raw = match super::iptables_run(runner, &[bin, "-S", &plan.chain()]) {
                Err(e) if missing(&e) => return Ok(false), result => result?,
            };
            let rules: Vec<_> = raw.lines().filter(|line| line.starts_with("-A ")).collect();
            if rules.len() != ipt_rules(plan, v6).len() || !(0..rules.len()).all(|i| rules.iter().any(|r| r.split_whitespace().any(|part| part.trim_matches('"') == format!("{tag}:{i}"))))
                || !rules.last().is_some_and(|rule| rule.ends_with("-j DROP")) || !hook_first(runner, bin, &plan.chain())? { return Ok(false); }
        }
        Ok(true)
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
