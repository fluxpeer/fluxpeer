// SPDX-License-Identifier: BSD-3-Clause
//! Linux forwarding rules owned by a single TUN interface.

use crate::apply::{self, ApplyError, Result};

#[cfg(any(target_os = "linux", test))]
mod forwarding;
pub(crate) mod client;

pub trait Firewall: Send + Sync {
    fn name(&self) -> &'static str;
    fn up(&self, phys: &str, tun: &str, options: &Options) -> Result;
    fn down(&self, phys: &str, tun: &str) -> Result;
    fn killswitch_on(&self, phys: &str, tun: &str) -> Result;
    fn killswitch_off(&self, phys: &str, tun: &str) -> Result;
}
#[derive(Default)]
pub(crate) struct Options {
    pub overlay_cidr: String,
    pub trust_external: bool,
}

pub struct Nft;
pub struct Iptables;

fn iptables_run(runner: &mut impl apply::Runner, args: &[&str]) -> Result<String> {
    let Some((bin, rest)) = args.split_first() else { return Err(ApplyError::new(args, "empty iptables command")); };
    let mut command = vec![*bin, "-w", "10"];
    command.extend_from_slice(rest);
    runner.run(&command, None)
}

pub fn detect() -> Result<Box<dyn Firewall>> {
    detect_with(&mut apply::System, std::env::var("FLUXPEER_FW_BACKEND").ok().as_deref())
}

fn detect_with(runner: &mut impl apply::Runner, requested: Option<&str>) -> Result<Box<dyn Firewall>> {
    match requested {
        Some("nft") => return Ok(Box::new(Nft)),
        Some("iptables") => return Ok(Box::new(Iptables)),
        Some(other) if !other.is_empty() => tracing::warn!(backend = other, "unknown FLUXPEER_FW_BACKEND"),
        _ => {}
    }
    // On Docker/iptables hosts, insert before their FORWARD policy/jumps. An
    // independent nft accept cannot override another base chain's drop.
    let mut error = match iptables_run(runner, &["iptables", "-S", "FORWARD"]) {
        Ok(_) => return Ok(Box::new(Iptables)),
        Err(e) if e.kind == std::io::ErrorKind::NotFound => e,
        Err(e) => return Err(e),
    };
    match runner.run(&["nft", "-j", "list", "ruleset"], None) {
        Ok(_) => Ok(Box::new(Nft)),
        Err(e) => { error.stderr.push_str(&format!("; nft fallback: {e}")); Err(error) }
    }
}

#[cfg(any(target_os = "linux", test))]
fn instance(tun: &str) -> Result<String> {
    if tun.is_empty() || tun.len() > 15 || tun.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b'_' && b != b'-') {
        return Err(ApplyError::new(&["firewall", tun], "invalid TUN interface name"));
    }
    Ok(format!("fluxpeer_{}", hex::encode(tun)))
}

#[cfg(any(target_os = "linux", test))]
fn permission_denied(error: &ApplyError) -> bool {
    let message = error.stderr.to_ascii_lowercase();
    error.kind == std::io::ErrorKind::PermissionDenied || message.contains("permission denied")
        || message.contains("operation not permitted") || message.contains("must be root")
}

#[cfg(any(target_os = "linux", test))]
fn sysctl_get_with(runner: &mut impl apply::Runner, key: &str) -> Result<bool> {
    let command = ["sysctl", "-n", key];
    match runner.run(&command, None)?.trim() {
        "0" => Ok(false), "1" => Ok(true),
        value => Err(ApplyError::new(&command, format!("invalid forwarding value: {value}"))),
    }
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


#[cfg(any(target_os = "linux", test))]
fn absent_table_or_chain(error: &ApplyError) -> bool {
    error.stderr.contains("Table does not exist") || error.stderr.contains("table does not exist")
        || error.stderr.contains("No chain/target/match") || error.stderr.contains("No such rule") || error.missing()
}

#[cfg(any(target_os = "linux", test))]
fn optional_iptables6(bin: &str, error: &ApplyError) -> bool {
    !permission_denied(error) && bin == "ip6tables" && (apply::ipv6_unavailable(error) || error.exit_code == Some(3) || absent_table_or_chain(error))
}

#[cfg(any(target_os = "linux", test))]
fn iptables_ensure_with(runner: &mut impl apply::Runner, bin: &str, table: &[&str], add_op: &str, rule: &[&str]) -> Result {
    let command = |op| { let mut c = vec![bin]; c.extend_from_slice(table); c.push(op); c.extend_from_slice(rule); c };
    let result = match iptables_run(runner, &command("-C")) {
        Ok(_) => Ok(()),
        Err(e) if e.exit_code == Some(1) && !permission_denied(&e) && !absent_table_or_chain(&e) => iptables_run(runner, &command(add_op)).map(|_| ()),
        Err(e) => Err(e),
    };
    match result {
        Err(e) if optional_iptables6(bin, &e) => { tracing::warn!(%e, "IPv6 firewall unavailable; continuing IPv4"); Ok(()) }
        result => result,
    }
}

#[cfg(any(target_os = "linux", test))]
fn iptables_drain_with(runner: &mut impl apply::Runner, bin: &str, table: &[&str], rule: &[&str]) -> Result {
    for _ in 0..256 {
        let mut c = vec![bin]; c.extend_from_slice(table); c.push("-C"); c.extend_from_slice(rule);
        match iptables_run(runner, &c) {
            Err(e) if !permission_denied(&e) && (e.exit_code == Some(1) || (e.exit_code.is_some() && absent_table_or_chain(&e)) || optional_iptables6(bin, &e)) => return Ok(()),
            result => { result?; }
        }
        let mut c = vec![bin]; c.extend_from_slice(table); c.push("-D"); c.extend_from_slice(rule);
        match iptables_run(runner, &c) {
            Err(e) if !permission_denied(&e) && ((e.exit_code.is_some() && absent_table_or_chain(&e)) || optional_iptables6(bin, &e)) => return Ok(()),
            result => { result?; }
        }
    }
    Err(ApplyError::new(&[bin, "-D"], "rule removal limit reached"))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
enum Operation { Up, Down, KillswitchOn, KillswitchOff }

macro_rules! backend {
    ($backend:ty, $name:literal) => {
        impl Firewall for $backend {
            fn name(&self) -> &'static str { $name }
            fn up(&self, phys: &str, tun: &str, options: &Options) -> Result { self.execute(phys, tun, "up", options) }
            fn down(&self, phys: &str, tun: &str) -> Result { self.execute(phys, tun, "down", &Options::default()) }
            fn killswitch_on(&self, phys: &str, tun: &str) -> Result { self.execute(phys, tun, "killswitch-on", &Options::default()) }
            fn killswitch_off(&self, phys: &str, tun: &str) -> Result { self.execute(phys, tun, "killswitch-off", &Options::default()) }
        }
        impl $backend {
            fn execute(&self, phys: &str, tun: &str, action: &str, _options: &Options) -> Result {
                #[cfg(target_os = "linux")]
                {
                    let op = match action {
                        "up" => Operation::Up, "down" => Operation::Down,
                        "killswitch-on" => Operation::KillswitchOn, _ => Operation::KillswitchOff,
                    };
                    execute_with(&mut apply::System, std::path::Path::new("/run/fluxpeer-firewall"), $name, op, (phys, tun), _options)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (&_options.overlay_cidr, _options.trust_external);
                    Err(ApplyError::new(&[$name, action, phys, tun], "Linux firewall backend is unavailable on this platform"))
                }
            }
        }
    };
}
backend!(Nft, "nft");
backend!(Iptables, "iptables");

#[cfg(any(target_os = "linux", test))]
fn execute_with(runner: &mut impl apply::Runner, root: &std::path::Path, backend: &str, op: Operation, interfaces: (&str, &str), options: &Options) -> Result {
    let (phys, tun) = interfaces;
    let id = instance(tun)?;
    // Serialize both rule edits and shared sysctl ownership across processes.
    let state = forwarding::State::lock(root)?;
    if matches!(op, Operation::Up) {
        let preflight = if backend == "iptables" { iptables_check_nft(runner, tun, phys) }
            else { nft_json(runner, &["nft", "-j", "list", "ruleset"]).map_err(ForwardCheckError::Inspection).and_then(|rules| nft_check_forward(&rules, tun, phys)) };
        check_external(preflight, options.trust_external)?;
        // Reject an absent/invalid source prefix before mutating any host state.
        options.overlay_cidr.parse::<fluxpeer_sdk::prefix::IpPrefix>()
            .map_err(|e| ApplyError::new(&["firewall", "overlay_cidr"], e.to_string()))?;
        state.acquire(runner, &id)?;
    }
    if backend == "nft" { nft_with(runner, op, phys, tun, &id, &options.overlay_cidr)?; }
    else { iptables_with(runner, op, phys, tun, &id, &options.overlay_cidr)?; }
    // A failed rule removal retains the forwarding lease for the cleanup retry.
    if matches!(op, Operation::Down) { state.release(runner, &id)?; }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn nft_unavailable(error: &ApplyError) -> bool {
    if permission_denied(error) { return false; }
    let message = error.stderr.to_ascii_lowercase();
    error.kind == std::io::ErrorKind::NotFound || message.contains("protocol not supported")
        || message.contains("operation not supported")
        || ((message.contains("invalid option") || message.contains("unrecognized option") || message.contains("unknown option"))
            && (message.contains("'j'") || message.contains("-j") || message.contains("json")))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug)]
enum ForwardCheckError { Policy(ApplyError), Inspection(ApplyError) }
#[cfg(any(target_os = "linux", test))]
impl From<ApplyError> for ForwardCheckError {
    fn from(error: ApplyError) -> Self { Self::Inspection(error) }
}

#[cfg(any(target_os = "linux", test))]
fn check_external(result: std::result::Result<(), ForwardCheckError>, trust: bool) -> Result {
    match result {
        Err(ForwardCheckError::Policy(error)) if trust => {
            tracing::warn!(%error, "firewall_trust_external=true: trusting external forwarding policy despite failed preflight"); Ok(())
        }
        Err(ForwardCheckError::Policy(mut error)) => {
            error.stderr.push_str("; verify external forwarding policy, then explicitly set local firewall_trust_external=true to trust it"); Err(error)
        }
        Err(ForwardCheckError::Inspection(error)) => Err(error),
        Ok(()) => Ok(()),
    }
}

#[cfg(any(target_os = "linux", test))]
fn interface_matches(pattern: &str, interface: &str) -> bool {
    pattern.strip_suffix('*').map_or(pattern == interface, |prefix| interface.starts_with(prefix))
}

#[cfg(any(target_os = "linux", test))]
fn match_strings(value: &serde_json::Value) -> Option<Vec<&str>> {
    if let Some(s) = value.as_str() { return (!s.starts_with('@')).then_some(vec![s]); }
    value.get("set")?.as_array()?.iter().map(|v| v.as_str()).collect()
}

#[cfg(any(target_os = "linux", test))]
fn unrelated_rule(expressions: &[serde_json::Value], tun: &str, phys: &str) -> bool {
    let matches: Vec<_> = expressions.iter().filter_map(|e| e.get("match")).collect();
    // Invalid conntrack packets are not an eligible outbound/established return
    // flow. Do not confuse a set containing other states with invalid-only.
    if matches.iter().any(|m| matches!(m.get("op").and_then(|v| v.as_str()), Some("==" | "in"))
        && m.pointer("/left/ct/key").and_then(|v| v.as_str()) == Some("state")
        && m.get("right").and_then(match_strings).is_some_and(|s| !s.is_empty() && s.iter().all(|s| *s == "invalid"))) { return true; }
    let possible = |input: &str, output: &str| matches.iter().all(|m| {
        let interface = match m.pointer("/left/meta/key").and_then(|v| v.as_str()) {
            Some("iifname") => input, Some("oifname") => output, _ => return true,
        };
        let Some(patterns) = m.get("right").and_then(match_strings) else { return true; };
        let matched = patterns.iter().any(|s| interface_matches(s, interface));
        match m.get("op").and_then(|v| v.as_str()) { Some("==" | "in") => matched, Some("!=") => !matched, _ => true }
    });
    !possible(tun, phys) && !possible(phys, tun)
}

#[cfg(any(target_os = "linux", test))]
fn killswitch_chain(id: &str) -> Result<String> {
    let raw = hex::decode(id.strip_prefix("fluxpeer_").unwrap_or("")).map_err(|e| ApplyError::new(&["firewall", "instance"], e.to_string()))?;
    let tun = String::from_utf8(raw).map_err(|e| ApplyError::new(&["firewall", "instance"], e.to_string()))?;
    Ok(format!("FPKS_{tun}"))
}

#[cfg(any(target_os = "linux", test))]
fn iptables_killswitch_on(runner: &mut impl apply::Runner, bin: &str, phys: &str, tun: &str, id: &str) -> Result {
    let chain = killswitch_chain(id)?;
    match iptables_run(runner, &[bin, "-S", &chain]) {
        Ok(_) => {}
        // A missing owned chain is normal on first use, including IPv6. Try
        // creating it before deciding that the whole IPv6 table is unavailable.
        Err(e) if !permission_denied(&e) && e.exit_code.is_some() && absent_table_or_chain(&e) => {
            match iptables_run(runner, &[bin, "-N", &chain]) {
                Err(e) if optional_iptables6(bin, &e) => return Ok(()),
                result => { result?; }
            }
        }
        Err(e) if optional_iptables6(bin, &e) => return Ok(()),
        Err(e) => return Err(e),
    }
    let tag = format!("{id}:killswitch");
    // The shared fp* namespace and this instance's custom name remain exempt.
    // An owned regular chain expresses the OR without broadening ACCEPT rules.
    for interface in ["fp+", tun] {
        iptables_ensure_with(runner, bin, &[], "-A", &[&chain, "-i", interface, "-m", "comment", "--comment", &tag, "-j", "RETURN"])?;
    }
    iptables_ensure_with(runner, bin, &[], "-A", &[&chain, "-m", "comment", "--comment", &tag, "-j", "DROP"])?;
    let jump = ["FORWARD", "-o", phys, "-m", "comment", "--comment", &tag, "-j", &chain];
    let rules = iptables_run(runner, &[bin, "-S", "FORWARD"])?;
    let leading = rules.lines().filter(|line| line.starts_with("-A "))
        .take_while(|line| line.contains("-j FPKS_"))
        .any(|line| line.split_whitespace().skip(1).map(|part| part.trim_matches('"')).eq(jump));
    if !leading {
        let mut args = vec![bin, "-I"]; args.extend(jump);
        iptables_run(runner, &args)?;
    }
    Ok(())
}

/// Read the actual owned rules so crash cleanup does not depend on the old
/// physical interface, source CIDR, backend choice, or Docker chain lifetime.
#[cfg(any(target_os = "linux", test))]
fn iptables_cleanup(runner: &mut impl apply::Runner, id: &str, only_killswitch: bool) -> Result {
    for bin in ["iptables", "ip6tables"] {
        for table in ["filter", "nat"] {
            let output = match iptables_run(runner, &[bin, "-t", table, "-S"]) {
                Err(e) if !permission_denied(&e) && (e.kind == std::io::ErrorKind::NotFound || optional_iptables6(bin, &e) || (e.exit_code.is_some() && absent_table_or_chain(&e))) => continue,
                result => result?,
            };
            for line in output.lines() {
                // Our comments and interface identifiers contain no spaces or
                // escapes. Foreign comments are never interpreted or modified.
                let args: Vec<_> = line.split_whitespace().map(|s| s.trim_matches('"')).collect();
                let owned = args.windows(2).any(|pair| match pair {
                    ["--comment", value] => ["forward", "nat", "killswitch"].iter().any(|kind|
                        (!only_killswitch || *kind == "killswitch") && *value == format!("{id}:{kind}")),
                    _ => false,
                });
                if args.first() != Some(&"-A") || !owned { continue; }
                iptables_drain_with(runner, bin, &["-t", table], &args.iter().skip(1).copied().collect::<Vec<_>>())?;
            }
        }
        let chain = killswitch_chain(id)?;
        match iptables_run(runner, &[bin, "-X", &chain]) {
            Err(e) if !permission_denied(&e) && (e.kind == std::io::ErrorKind::NotFound || optional_iptables6(bin, &e) || (e.exit_code.is_some() && absent_table_or_chain(&e))) => {}
            result => { result?; }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn has_lease(tun: &str) -> Result<bool> {
    has_lease_at(std::path::Path::new("/run/fluxpeer-firewall"), tun)
}

#[cfg(any(target_os = "linux", test))]
fn has_lease_at(root: &std::path::Path, tun: &str) -> Result<bool> {
    let path = root.join(format!("{}.lease", instance(tun)?));
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ApplyError::io(&["firewall", "lease", &path.to_string_lossy()], error)),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn recover(tun: &str) -> Result {
    recover_with(&mut apply::System, std::path::Path::new("/run/fluxpeer-firewall"), tun)
}

#[cfg(any(target_os = "linux", test))]
fn recover_with(runner: &mut impl apply::Runner, root: &std::path::Path, tun: &str) -> Result {
    let id = instance(tun)?;
    let state = forwarding::State::lock(root)?;
    let nft = match nft_with(runner, Operation::Down, "", tun, &id, "") {
        Err(e) if nft_unavailable(&e) => Ok(()), result => result,
    };
    let iptables = iptables_cleanup(runner, &id, false);
    apply::all([nft, iptables])?;
    state.release(runner, &id)
}

/// iptables-nft can edit its own FORWARD chain, but cannot override a native
/// nft drop in another base chain. Legacy iptables cannot edit any nft chain.
#[cfg(any(target_os = "linux", test))]
fn iptables_check_nft(runner: &mut impl apply::Runner, tun: &str, phys: &str) -> std::result::Result<(), ForwardCheckError> {
    let mut ruleset = match nft_json(runner, &["nft", "-j", "list", "ruleset"]) {
        Err(e) if nft_unavailable(&e) => return Ok(()),
        result => result?,
    };
    match nft_check_forward(&ruleset, tun, phys) {
        Ok(()) => return Ok(()),
        Err(ForwardCheckError::Inspection(error)) => return Err(error.into()),
        Err(ForwardCheckError::Policy(_)) => {},
    }
    let mut managed = Vec::new();
    for (bin, family) in [("iptables", "ip"), ("ip6tables", "ip6")] {
        match iptables_run(runner, &[bin, "--version"]) {
            Ok(version) if version.contains("(nf_tables)") => managed.push(family),
            Ok(_) => {}
            Err(e) if optional_iptables6(bin, &e) => {}
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(items) = ruleset.get_mut("nftables").and_then(|v| v.as_array_mut()) {
        items.retain(|item| !item.get("chain").is_some_and(|c|
            c.get("family").and_then(|v| v.as_str()).is_some_and(|f| managed.contains(&f))
                && c.get("table").and_then(|v| v.as_str()) == Some("filter")
                && c.get("name").and_then(|v| v.as_str()) == Some("FORWARD")));
    }
    nft_check_forward(&ruleset, tun, phys)
}

#[cfg(any(target_os = "linux", test))]
fn forward_policy_drop(output: &str) -> bool {
    output.lines().any(|line| line.split_whitespace().eq(["-P", "FORWARD", "DROP"]))
}

#[cfg(any(target_os = "linux", test))]
fn iptables_with(runner: &mut impl apply::Runner, op: Operation, phys: &str, tun: &str, id: &str, overlay_cidr: &str) -> Result {
    if matches!(op, Operation::Down | Operation::KillswitchOff) {
        return iptables_cleanup(runner, id, matches!(op, Operation::KillswitchOff));
    }
    // Match nft inet's dual-family forward guards, including its WAN ingress
    // protection. MASQUERADE below is restricted to the overlay family on both.
    for bin in ["iptables", "ip6tables"] {
        let tag = format!("{id}:forward");
        let nat_tag = format!("{id}:nat");
        let nat = ["POSTROUTING", "-s", overlay_cidr, "-o", phys, "-m", "comment", "--comment", &nat_tag, "-j", "MASQUERADE"];
        if matches!(op, Operation::KillswitchOn | Operation::KillswitchOff) {
            if matches!(op, Operation::KillswitchOn) { iptables_killswitch_on(runner, bin, phys, tun, id)?; }
            continue;
        }
        if matches!(op, Operation::Up) {
            let forward = match iptables_run(runner, &[bin, "-S", "FORWARD"]) {
                Err(e) if optional_iptables6(bin, &e) => { tracing::warn!(%e, "IPv6 firewall unavailable"); continue; }
                result => result?,
            };
            tracing::debug!(bin, drop_policy = forward_policy_drop(&forward), "installing scoped forwarding rules");
        }
        // Probe instead of creating Docker's chain. Cleanup also probes it,
        // since Docker may have created/deleted the chain after our setup.
        let docker = match iptables_run(runner, &[bin, "-S", "DOCKER-USER"]) {
            Ok(_) => true,
            Err(e) if !permission_denied(&e) && ((e.exit_code.is_some() && absent_table_or_chain(&e)) || optional_iptables6(bin, &e)) => false,
            Err(e) => return Err(e),
        };
        for chain in std::iter::once("FORWARD").chain(docker.then_some("DOCKER-USER")) {
            // Install the WAN-only guard first, then move our ACCEPT rules in
            // front of it. Reinsert existing ACCEPTs too: an upgrade from the
            // previous ruleset must preserve this order, not leave DROP first.
            // All three precede external rules without affecting LAN ingress.
            let outbound = [chain, "-i", tun, "-o", phys, "-m", "comment", "--comment", &tag, "-j", "ACCEPT"];
            let inbound = [chain, "-i", phys, "-o", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", &tag, "-j", "ACCEPT"];
            let ingress = [chain, "-i", phys, "-o", tun, "-m", "conntrack", "!", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", &tag, "-j", "DROP"];
            iptables_ensure_with(runner, bin, &[], "-I", &ingress)?;
            iptables_drain_with(runner, bin, &[], &outbound)?;
            iptables_drain_with(runner, bin, &[], &inbound)?;
            iptables_ensure_with(runner, bin, &[], "-I", &outbound)?;
            iptables_ensure_with(runner, bin, &[], "-I", &inbound)?;
        }
        if overlay_cidr.contains(':') == (bin == "ip6tables") {
            iptables_ensure_with(runner, bin, &["-t", "nat"], "-A", &nat)?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn nft_json(runner: &mut impl apply::Runner, command: &[&str]) -> Result<serde_json::Value> {
    let output = runner.run(command, None)?;
    serde_json::from_str(&output).map_err(|e| ApplyError::new(command, format!("invalid nft JSON: {e}")))
}

/// Conservatively reject potential drops reachable from an external forward
/// base chain. Proven interface exclusions and invalid-only drops are harmless;
/// other predicates and verdict maps remain conservative unless explicitly trusted.
#[cfg(any(target_os = "linux", test))]
fn nft_check_forward(ruleset: &serde_json::Value, tun: &str, phys: &str) -> std::result::Result<(), ForwardCheckError> {
    let command = ["nft", "-j", "list", "ruleset"];
    let items = ruleset.get("nftables").and_then(|v| v.as_array())
        .ok_or_else(|| ApplyError::new(&command, "missing nftables ruleset array"))?;
    for base in items.iter().filter_map(|v| v.get("chain")) {
        let family = base.get("family").and_then(|v| v.as_str()).unwrap_or("");
        let table = base.get("table").and_then(|v| v.as_str()).unwrap_or("");
        if !matches!(family, "inet" | "ip" | "ip6") || table.starts_with("fluxpeer_")
            || base.get("hook").and_then(|v| v.as_str()) != Some("forward") { continue; }
        let name = base.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let fail = || ApplyError::new(&command, format!("external forward chain {family} {table} {name} can drop traffic; cannot override with an independent nft accept"));
        if base.get("policy").and_then(|v| v.as_str()) == Some("drop") { return Err(ForwardCheckError::Policy(fail())); }
        let mut pending = vec![name.to_string()];
        let mut seen = std::collections::HashSet::new();
        while let Some(chain) = pending.pop() {
            if !seen.insert(chain.clone()) { continue; }
            for rule in items.iter().filter_map(|v| v.get("rule")).filter(|r|
                r.get("family").and_then(|v| v.as_str()) == Some(family)
                    && r.get("table").and_then(|v| v.as_str()) == Some(table)
                    && r.get("chain").and_then(|v| v.as_str()) == Some(chain.as_str())) {
                let expressions = rule.get("expr").and_then(|v| v.as_array()).ok_or_else(|| ApplyError::new(&command, "malformed nft forward rule"))?;
                if unrelated_rule(expressions, tun, phys) { continue; }
                for expr in expressions {
                    if expr.get("drop").is_some() || expr.get("reject").is_some() || expr.get("vmap").is_some() { return Err(ForwardCheckError::Policy(fail())); }
                    for target in ["jump", "goto"].iter().filter_map(|key| expr.get(key)) {
                        pending.push(target.get("target").and_then(|v| v.as_str()).ok_or_else(|| ApplyError::new(&command, "malformed nft forward rule"))?.to_string());
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn nft_with(runner: &mut impl apply::Runner, op: Operation, phys: &str, tun: &str, id: &str, overlay_cidr: &str) -> Result {
    match op {
        Operation::Up => {
            // One nft transaction: replace only this instance's table. Quoted
            // interface strings are JSON escaped (also valid nft string syntax).
            let phys = serde_json::to_string(phys).map_err(|e| ApplyError::new(&["nft"], e.to_string()))?;
            let tun = serde_json::to_string(tun).map_err(|e| ApplyError::new(&["nft"], e.to_string()))?;
            // Both backends guard forwarding in both families (including new
            // unsolicited WAN ingress), but NAT only the overlay address family.
            let family = if overlay_cidr.contains(':') { "ipv6" } else { "ipv4" };
            let script = format!("add table inet {id}\ndelete table inet {id}\ntable inet {id} {{\n chain postrouting {{ type nat hook postrouting priority srcnat; policy accept; meta nfproto {family} iifname {tun} oifname {phys} masquerade; }}\n chain forward {{ type filter hook forward priority filter; policy accept; iifname {tun} oifname {phys} accept; iifname {phys} oifname {tun} ct state established,related accept; iifname {phys} oifname {tun} ct state != {{ established, related }} drop; }}\n}}\n");
            runner.run(&["nft", "-f", "-"], Some(&script))?;
        }
        Operation::Down => {
            let guard = format!("{id}_forward_guard");
            apply::all([id, guard.as_str()].into_iter().map(|table| {
                match runner.run(&["nft", "delete", "table", "inet", table], None) {
                    Err(e) if !permission_denied(&e) && e.exit_code.is_some() && e.missing() => Ok(()),
                    result => result.map(|_| ()),
                }
            }))?;
        }
        Operation::KillswitchOn | Operation::KillswitchOff => {
            // NAT Up atomically replaces only the NAT/forwarding table. Keep
            // protection in its own table so an Up cannot silently remove it.
            let table = format!("{id}_forward_guard");
            if matches!(op, Operation::KillswitchOff) {
                match runner.run(&["nft", "delete", "table", "inet", &table], None) {
                    Err(e) if !permission_denied(&e) && e.exit_code.is_some() && e.missing() => {},
                    result => { result?; },
                }
            } else {
                let phys = serde_json::to_string(phys).map_err(|e| ApplyError::new(&["nft"], e.to_string()))?;
                let tun = serde_json::to_string(tun).map_err(|e| ApplyError::new(&["nft"], e.to_string()))?;
                let script = format!("add table inet {table}\ndelete table inet {table}\ntable inet {table} {{ chain forward {{ type filter hook forward priority -150; policy accept; oifname {phys} iifname != \"fp*\" iifname != {tun} drop; }} }}\n");
                runner.run(&["nft", "-f", "-"], Some(&script))?;
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use apply::test_support::{Scripted, error};

    fn options() -> Options { Options { overlay_cidr: "100.72.0.0/24".into(), trust_external: false } }

    #[test]
    fn ip6tables_exit_three_permissions_are_never_optional_even_with_missing_text() {
        for message in ["Permission denied", "can't initialize table: Permission denied (you must be root)", "Table does not exist: Operation not permitted"] {
            for op in ["ensure", "drain"] {
                let mut runner = Scripted::new(vec![Err(error(Some(3), message))]);
                let result = if op == "ensure" { iptables_ensure_with(&mut runner, "ip6tables", &[], "-I", &["FORWARD"]) }
                    else { iptables_drain_with(&mut runner, "ip6tables", &[], &["FORWARD"]) };
                assert_eq!(result.unwrap_err().exit_code, Some(3));
                assert_eq!(runner.commands.len(), 1);
            }
        }
    }

    #[test]
    fn backend_selection_prefers_iptables_for_docker_and_falls_back_read_only() {
        let mut runner = Scripted::new(vec![Ok("-P FORWARD DROP\n-A FORWARD -j DOCKER-USER".into())]);
        assert_eq!(detect_with(&mut runner, None).unwrap().name(), "iptables");
        assert_eq!(runner.commands, [vec!["iptables", "-w", "10", "-S", "FORWARD"]]);
        let mut runner = Scripted::new(vec![Err(error(None, "missing executable")), Ok(r#"{"nftables":[]}"#.into())]);
        assert_eq!(detect_with(&mut runner, None).unwrap().name(), "nft");
        assert_eq!(runner.commands[1], ["nft", "-j", "list", "ruleset"]);
    }

    #[test]
    fn mixed_hosts_only_skip_forward_chains_managed_by_iptables_nft() {
        use serde_json::json;
        let forward = json!({"chain":{"family":"ip","table":"filter","name":"FORWARD","hook":"forward","policy":"drop"}});
        let external = json!({"chain":{"family":"inet","table":"firewalld","name":"forward","hook":"forward","policy":"drop"}});
        for (version, items, allowed) in [
            ("iptables v1.8.11 (nf_tables)", vec![forward.clone()], true),
            ("iptables v1.8.11 (legacy)", vec![forward.clone()], false),
            ("iptables v1.8.11 (nf_tables)", vec![forward, external], false),
        ] {
            let mut runner = Scripted::new(vec![Ok(json!({"nftables":items}).to_string()), Ok(version.into()), Ok(version.into())]);
            assert_eq!(iptables_check_nft(&mut runner, "fp0", "eth0").is_ok(), allowed);
            assert_eq!(runner.commands, [vec!["nft", "-j", "list", "ruleset"], vec!["iptables", "-w", "10", "--version"], vec!["ip6tables", "-w", "10", "--version"]]);
        }
        let mut runner = Scripted::new(vec![Err(error(None, "missing executable"))]);
        iptables_check_nft(&mut runner, "fp0", "eth0").unwrap();
        let mut runner = Scripted::new(vec![Err(error(Some(1), "Permission denied"))]);
        assert!(iptables_check_nft(&mut runner, "fp0", "eth0").is_err());
    }

    #[test]
    fn nft_external_drop_policy_rules_jump_and_verdict_maps_fail_visibly() {
        use serde_json::json;
        let base = json!({"chain":{"family":"inet","table":"external","name":"fwd","hook":"forward","policy":"accept"}});
        let rule = |chain: &str, expr| json!({"rule":{"family":"inet","table":"external","chain":chain,"expr":[expr]}});
        for items in [
            vec![json!({"chain":{"family":"inet","table":"external","name":"fwd","hook":"forward","policy":"drop"}})],
            vec![base.clone(), rule("fwd", json!({"drop":null}))],
            vec![base.clone(), rule("fwd", json!({"jump":{"target":"rejects"}})), rule("rejects", json!({"reject":null}))],
            vec![base.clone(), rule("fwd", json!({"vmap":{"key":{},"data":"@verdicts"}}))],
        ] {
            let ruleset = json!({"nftables":items});
            assert!(matches!(nft_check_forward(&ruleset, "fp0", "eth0"), Err(ForwardCheckError::Policy(error)) if error.stderr.contains("external forward chain")));
            let mut runner = Scripted::new(vec![Ok(ruleset.to_string())]);
            let dir = tempfile::tempdir().unwrap();
            assert!(execute_with(&mut runner, dir.path(), "nft", Operation::Up, ("eth0", "fp0"), &options()).is_err());
            assert!(!dir.path().join("baseline.json").exists());
            assert_eq!(runner.commands, [vec!["nft", "-j", "list", "ruleset"]]);
        }
        // An INPUT-only drop is unrelated; ordinary ACCEPT forward chains coexist.
        nft_check_forward(&json!({"nftables":[base, rule("fwd", json!({"accept":null})), rule("input", json!({"drop":null}))]}), "fp0", "eth0").unwrap();
        assert!(nft_check_forward(&json!({"unexpected":[]}), "fp0", "eth0").is_err());
    }

    #[derive(Default)]
    struct Host {
        commands: Vec<Vec<String>>,
        scripts: Vec<String>,
        rules: std::collections::HashSet<Vec<String>>,
        tables: std::collections::HashMap<String, String>,
        forwarding: bool,
        fail_delete: bool,
        no_docker: bool,
        no_ipv6: bool,
        forward_accept: bool,
        fail_ingress_add: bool,
        external_rules: Option<String>,
    }
    impl apply::Runner for Host {
        fn run(&mut self, args: &[&str], input: Option<&str>) -> Result<String> {
            self.commands.push(args.iter().map(|s| s.to_string()).collect());
            let mut normalized = args.to_vec();
            if matches!(normalized.as_slice(), ["iptables" | "ip6tables", "-w", "10", ..]) { normalized.drain(1..3); }
            let args = normalized.as_slice();
            if self.no_ipv6 && args.first() == Some(&"ip6tables") { return Err(error(Some(3), "Table does not exist")); }
            if self.no_docker && args == ["iptables", "-S", "DOCKER-USER"] { return Err(error(Some(1), "No chain/target/match by that name.")); }
            if self.fail_ingress_add && args.contains(&"-I") && args.contains(&"!") {
                return Err(error(Some(4), "ingress DROP install failed"));
            }
            match args {
                ["sysctl", "-n", _] => return Ok(u8::from(self.forwarding).to_string()),
                ["sysctl", "-w", value] => { self.forwarding = value.ends_with("=1"); return Ok(String::new()); }
                ["nft", "-j", "list", "ruleset"] => return Ok(self.external_rules.clone().unwrap_or_else(|| r#"{"nftables":[]}"#.into())),
                ["nft", "-f", "-"] => {
                    let script = input.unwrap();
                    let name = script.lines().next().unwrap().strip_prefix("add table inet ").unwrap();
                    self.tables.insert(name.into(), script.into()); self.scripts.push(script.into());
                    return Ok(String::new());
                }
                ["nft", "delete", "table", "inet", name] => {
                    if self.fail_delete { return Err(error(Some(1), "Permission denied")); }
                    self.tables.remove(*name); return Ok(String::new());
                }
                [bin, "-t", table, "-S"] => {
                    let mut lines = Vec::new();
                    for rule in &self.rules {
                        if rule.first().map(String::as_str) != Some(*bin) { continue; }
                        if *table == "nat" && rule.get(1).is_some_and(|s| s == "-t") {
                            lines.push(format!("-A {}", rule.iter().skip(3).cloned().collect::<Vec<_>>().join(" ")));
                        } else if *table == "filter" && rule.get(1).is_some_and(|s| s != "-t") {
                            lines.push(format!("-A {}", rule.iter().skip(1).cloned().collect::<Vec<_>>().join(" ")));
                        }
                    }
                    return Ok(lines.join("\n"));
                }
                [_, "-X", _] => return Ok(String::new()),
                [_, "-S", chain] if chain.starts_with("FPKS_") => return Ok(String::new()),
                [_, "-S", "FORWARD"] => return Ok(format!("-P FORWARD {}\n-A FORWARD -j DOCKER-USER", if self.forward_accept { "ACCEPT" } else { "DROP" })),
                [_, "-S", "DOCKER-USER"] => return Ok("-N DOCKER-USER\n-A DOCKER-USER -j DROP".into()),
                _ => {}
            }
            let mut normalized = args.to_vec();
            if matches!(normalized.as_slice(), [_, "-t", "filter", ..]) { normalized.drain(1..3); }
            let args = normalized.as_slice();
            let idx = args.iter().position(|a| matches!(*a, "-C" | "-I" | "-A" | "-D")).expect("unknown test command");
            let key: Vec<String> = args.iter().enumerate().filter(|(i, _)| *i != idx).map(|(_, s)| s.to_string()).collect();
            match args[idx] {
                "-C" if !self.rules.contains(&key) => Err(error(Some(1), "Bad rule")),
                "-C" => Ok(String::new()),
                "-I" | "-A" => { self.rules.insert(key); Ok(String::new()) }
                "-D" => {
                    if self.fail_delete { return Err(error(Some(4), "Permission denied")); }
                    self.rules.remove(&key); Ok(String::new())
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn docker_drop_commands_are_scoped_insertions_and_cleanup_only_owns_comments() {
        let mut host = Host::default();
        let a = instance("fp0").unwrap(); let b = instance("fp1").unwrap();
        // An identical untagged admin rule must survive our cleanup.
        let foreign: Vec<_> = ["iptables", "FORWARD", "-i", "fp0", "-j", "ACCEPT"].into_iter().map(str::to_string).collect();
        host.rules.insert(foreign.clone());
        iptables_with(&mut host, Operation::Up, "eth0", "fp0", &a, "100.72.0.0/24").unwrap();
        iptables_with(&mut host, Operation::Up, "eth0", "fp1", &b, "100.72.0.0/24").unwrap();
        let count = host.rules.len();
        iptables_with(&mut host, Operation::Up, "eth0", "fp0", &a, "100.72.0.0/24").unwrap();
        assert_eq!(host.rules.len(), count);
        for bin in ["iptables", "ip6tables"] {
            for chain in ["FORWARD", "DOCKER-USER"] {
                let expected = [
                    vec![bin, "-w", "10", "-I", chain, "-i", "fp0", "-o", "eth0", "-m", "comment", "--comment", &format!("{a}:forward"), "-j", "ACCEPT"],
                    vec![bin, "-w", "10", "-I", chain, "-i", "eth0", "-o", "fp0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", &format!("{a}:forward"), "-j", "ACCEPT"],
                ].map(|v| v.into_iter().map(str::to_string).collect::<Vec<_>>());
                let out = host.commands.iter().position(|c| c == &expected[0]).unwrap();
                let incoming = host.commands.iter().position(|c| c == &expected[1]).unwrap();
                assert!(out < incoming, "return rule inserted last at the front of the chain");
            }
        }
        assert!(host.commands.contains(&vec!["iptables", "-w", "10", "-t", "nat", "-A", "POSTROUTING", "-s", "100.72.0.0/24", "-o", "eth0", "-m", "comment", "--comment", &format!("{a}:nat"), "-j", "MASQUERADE"].into_iter().map(str::to_string).collect()));
        iptables_with(&mut host, Operation::KillswitchOn, "eth0", "fp0", &a, "100.72.0.0/24").unwrap();
        iptables_with(&mut host, Operation::KillswitchOff, "eth0", "fp0", &a, "100.72.0.0/24").unwrap();
        iptables_with(&mut host, Operation::Down, "eth0", "fp0", &a, "100.72.0.0/24").unwrap();
        assert!(host.rules.contains(&foreign));
        assert_eq!(host.rules.len(), 14); // thirteen rules for B plus the administrator's rule
        assert!(host.rules.iter().filter(|r| *r != &foreign).all(|r| r.iter().any(|s| s.starts_with(&b))));
    }

    #[test]
    fn wan_ingress_guard_precedes_external_rules_on_accept_hosts_and_upgrades_existing_rules() {
        let mut host = Host { forward_accept: true, ..Host::default() };
        let id = instance("custom0").unwrap();
        let tag = format!("{id}:forward");
        // Simulate a pre-T-0032 installation and a host allowing all forwarding.
        for bin in ["iptables", "ip6tables"] {
            for chain in ["FORWARD", "DOCKER-USER"] {
                for tail in [
                    vec!["-i", "custom0", "-o", "wan0", "-m", "comment", "--comment", &tag, "-j", "ACCEPT"],
                    vec!["-i", "wan0", "-o", "custom0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", &tag, "-j", "ACCEPT"],
                    vec!["-j", "ACCEPT"],
                ] {
                    host.rules.insert([vec![bin, chain], tail].concat().into_iter().map(str::to_string).collect());
                }
            }
        }
        iptables_with(&mut host, Operation::Up, "wan0", "custom0", &id, "100.72.0.0/24").unwrap();
        for bin in ["iptables", "ip6tables"] {
            for chain in ["FORWARD", "DOCKER-USER"] {
                let insertions: Vec<_> = host.commands.iter().filter(|c| c.first().is_some_and(|v| v == bin)
                    && c.get(3).is_some_and(|v| v == "-I") && c.get(4).is_some_and(|v| v == chain)).cloned().collect();
                let expected = [
                    vec![bin, "-w", "10", "-I", chain, "-i", "wan0", "-o", "custom0", "-m", "conntrack", "!", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", &tag, "-j", "DROP"],
                    vec![bin, "-w", "10", "-I", chain, "-i", "custom0", "-o", "wan0", "-m", "comment", "--comment", &tag, "-j", "ACCEPT"],
                    vec![bin, "-w", "10", "-I", chain, "-i", "wan0", "-o", "custom0", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", &tag, "-j", "ACCEPT"],
                ].map(|v| v.into_iter().map(str::to_string).collect::<Vec<_>>());
                // Each -I inserts at position 1: return ACCEPT, outbound ACCEPT,
                // WAN-only DROP, then the preexisting external ACCEPT.
                assert_eq!(insertions, expected);
            }
        }
        let count = host.rules.len();
        iptables_with(&mut host, Operation::Up, "wan0", "custom0", &id, "100.72.0.0/24").unwrap();
        assert_eq!(host.rules.len(), count);
        iptables_with(&mut host, Operation::Down, "changed-wan", "custom0", &id, "").unwrap();
        assert_eq!(host.rules.len(), 4);
        assert!(host.rules.iter().all(|r| r.len() == 4 && r[2] == "-j" && r[3] == "ACCEPT"));
    }

    #[test]
    fn wan_ingress_install_failure_is_visible_and_retains_lease_for_retry_and_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = Host { forward_accept: true, fail_ingress_add: true, ..Host::default() };
        let result = execute_with(&mut host, dir.path(), "iptables", Operation::Up, ("wan0", "fp0"), &options());
        assert!(result.unwrap_err().stderr.contains("ingress DROP install failed"));
        assert!(has_lease_at(dir.path(), "fp0").unwrap());
        host.fail_ingress_add = false;
        execute_with(&mut host, dir.path(), "iptables", Operation::Up, ("wan0", "fp0"), &options()).unwrap();
        assert!(host.rules.iter().any(|r| r.iter().any(|v| v == "!")));
        recover_with(&mut host, dir.path(), "fp0").unwrap();
        assert!(host.rules.is_empty()); assert!(!host.forwarding);
        assert!(!has_lease_at(dir.path(), "fp0").unwrap());
    }

    #[test]
    fn nft_wan_ingress_guard_is_scoped_and_ordered_after_return_accept() {
        let id = instance("custom0").unwrap();
        let mut runner = Host::default();
        nft_with(&mut runner, Operation::Up, "wan0", "custom0", &id, "100.72.0.0/24").unwrap();
        assert_eq!(runner.commands, [vec!["nft", "-f", "-"]]);
        let script = &runner.scripts[0];
        assert!(script.contains("iifname \"wan0\" oifname \"custom0\" ct state established,related accept; iifname \"wan0\" oifname \"custom0\" ct state != { established, related } drop;"));
        assert!(!script.contains("lan0"));
    }

    #[test]
    fn complete_two_instance_lifecycle_preserves_rules_and_forwarding_on_both_backends() {
        for backend in ["nft", "iptables"] {
            for order in [["fp0", "fp1"], ["fp1", "fp0"]] {
                let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
                execute_with(&mut host, dir.path(), backend, Operation::Up, ("eth0", "fp0"), &options()).unwrap();
                execute_with(&mut host, dir.path(), backend, Operation::Up, ("eth0", "fp1"), &options()).unwrap();
                assert!(host.forwarding);
                if backend == "nft" {
                    assert_eq!(host.tables.len(), 2);
                    assert!(host.scripts[0].contains("iifname \"fp0\" oifname \"eth0\" masquerade"));
                    assert!(host.scripts[0].contains("iifname \"fp0\" oifname \"eth0\" accept"));
                    assert!(host.scripts[0].contains("iifname \"eth0\" oifname \"fp0\" ct state established,related accept"));
                    assert!(!host.scripts[0].contains("oifname \"fp0\" accept"));
                    assert!(!host.scripts[0].contains(&instance("fp1").unwrap()));
                }
                host.fail_delete = true;
                assert!(execute_with(&mut host, dir.path(), backend, Operation::Down, ("eth0", order[0]), &options()).is_err());
                assert!(dir.path().join(format!("{}.lease", instance(order[0]).unwrap())).exists());
                host.fail_delete = false;
                execute_with(&mut host, dir.path(), backend, Operation::Down, ("eth0", order[0]), &options()).unwrap();
                assert!(host.forwarding);
                if backend == "nft" { assert!(host.tables.contains_key(&instance(order[1]).unwrap())); assert_eq!(host.tables.len(), 1); }
                else { assert_eq!(host.rules.len(), 13); }
                execute_with(&mut host, dir.path(), backend, Operation::Down, ("eth0", order[1]), &options()).unwrap();
                assert!(!host.forwarding);
                assert!(host.tables.is_empty()); assert!(host.rules.is_empty());
            }
        }
    }

    #[test]
    fn absent_docker_and_optional_ipv6_forward_probe_do_not_block_ipv4() {
        assert!(forward_policy_drop("-P FORWARD DROP\n-A FORWARD -j DOCKER-USER"));
        assert!(!forward_policy_drop("-P FORWARD ACCEPT\n-A FORWARD -j DROP"));
        let mut host = Host { no_docker: true, no_ipv6: true, ..Host::default() };
        iptables_with(&mut host, Operation::Up, "wan0", "fp0", &instance("fp0").unwrap(), "100.72.0.0/24").unwrap();
        assert_eq!(host.rules.len(), 4);
        assert!(host.rules.iter().all(|r| !r.iter().any(|v| v == "DOCKER-USER")));
        let v6: Vec<_> = host.commands.iter().filter(|c| c.first().is_some_and(|s| s == "ip6tables")).collect();
        assert_eq!(v6, [&vec!["ip6tables", "-w", "10", "-S", "FORWARD"]]);
        assert!(host.commands.iter().all(|c| c.get(1).is_some_and(|s| s == "-w")));
    }

    #[test]
    fn startup_reclaims_stale_lease_rules_and_killswitch_with_exit_disabled() {
        for backend in ["nft", "iptables"] {
            let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
            execute_with(&mut host, dir.path(), backend, Operation::Up, ("old-wan", "fp0"), &options()).unwrap();
            if backend == "iptables" {
                iptables_with(&mut host, Operation::KillswitchOn, "old-wan", "fp0", &instance("fp0").unwrap(), "").unwrap();
            }
            assert!(host.forwarding);
            // Fresh in-memory state after a crash, with current exit setting OFF.
            let mut runtime = crate::NatInstall::default();
            crate::recover_nat(&mut runtime, false, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")).unwrap();
            crate::reconcile_nat(&mut runtime, false, || panic!("disabled exit must not discover egress"), |_, _| panic!("disabled exit must not install NAT")).unwrap();
            crate::recover_nat(&mut runtime, false, || panic!("already recovered"), || panic!("startup recovery must only run once after success")).unwrap();
            assert!(!host.forwarding); assert!(host.tables.is_empty()); assert!(host.rules.is_empty());
            assert!(!dir.path().join(format!("{}.lease", instance("fp0").unwrap())).exists());
            recover_with(&mut host, dir.path(), "fp0").unwrap();
        }
    }

    #[test]
    fn failed_startup_cleanup_retries_and_rule_only_residue_is_removed() {
        let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
        let id = instance("fp0").unwrap();
        iptables_with(&mut host, Operation::Up, "old-wan", "fp0", &id, "100.72.0.0/24").unwrap();
        assert!(!dir.path().join(format!("{id}.lease")).exists());
        let mut runtime = crate::NatInstall::default(); host.fail_delete = true;
        assert!(crate::recover_nat(&mut runtime, true, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")).is_err());
        assert!(!runtime.recovered); host.fail_delete = false;
        crate::recover_nat(&mut runtime, true, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")).unwrap();
        assert!(host.rules.is_empty());
    }

    #[test]
    fn disabled_exit_without_lease_defers_cleanup_and_acknowledges_epoch() {
        let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
        let id = instance("fp0").unwrap();
        iptables_with(&mut host, Operation::Up, "old-wan", "fp0", &id, "100.72.0.0/24").unwrap();
        // Another interface's lease must not prevent best-effort cleanup here.
        std::fs::write(dir.path().join(format!("{}.lease", instance("fp1").unwrap())), "").unwrap();
        let mut runtime = crate::NatInstall::default(); let mut status = apply::Status::default();
        host.fail_delete = true;
        status.complete(1, crate::recover_nat(&mut runtime, false, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")));
        assert_eq!(status.applied_epoch, Some(1)); assert!(status.last_error.is_none());
        assert!(runtime.recovery_deferred); assert!(!runtime.recovered); assert!(!host.rules.is_empty());
        crate::recover_nat(&mut runtime, false, || has_lease_at(dir.path(), "fp0"), || panic!("no repeated cleanup while disabled without a lease")).unwrap();
        // Enabling exit must retry and propagate the same cleanup failure.
        status.complete(2, crate::recover_nat(&mut runtime, true, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")));
        assert_eq!(status.applied_epoch, Some(1)); assert!(status.last_error.is_some());
        host.fail_delete = false;
        status.complete(2, crate::recover_nat(&mut runtime, true, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")));
        assert_eq!(status.applied_epoch, Some(2)); assert!(status.last_error.is_none());
        assert!(runtime.recovered); assert!(!runtime.recovery_deferred); assert!(host.rules.is_empty());
    }

    #[test]
    fn disabled_exit_with_lease_keeps_cleanup_failure_and_restoration_obligation() {
        for deferred in [false, true] {
            let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
            let mut runtime = crate::NatInstall::default(); let mut status = apply::Status::default();
            if deferred {
                crate::recover_nat(&mut runtime, false, || has_lease_at(dir.path(), "fp0"), || Err(ApplyError::new(&["firewall"], "cleanup denied"))).unwrap();
            }
            // Also cover a lease appearing after an earlier best-effort failure.
            execute_with(&mut host, dir.path(), "iptables", Operation::Up, ("old-wan", "fp0"), &options()).unwrap();
            host.fail_delete = true;
            status.complete(1, crate::recover_nat(&mut runtime, false, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")));
            assert_eq!(status.applied_epoch, None); assert!(status.last_error.is_some());
            assert!(host.forwarding); assert!(has_lease_at(dir.path(), "fp0").unwrap()); assert!(!runtime.recovered);
            host.fail_delete = false;
            status.complete(1, crate::recover_nat(&mut runtime, false, || has_lease_at(dir.path(), "fp0"), || recover_with(&mut host, dir.path(), "fp0")));
            assert_eq!(status.applied_epoch, Some(1)); assert!(status.last_error.is_none());
            assert!(!host.forwarding); assert!(!has_lease_at(dir.path(), "fp0").unwrap()); assert!(runtime.recovered);
        }
    }

    #[test]
    fn unknown_lease_presence_cannot_defer_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let invalid_root = dir.path().join("not-a-directory"); std::fs::write(&invalid_root, "").unwrap();
        assert!(has_lease_at(&invalid_root, "fp0").is_err());
        let mut runtime = crate::NatInstall::default();
        assert!(crate::recover_nat(&mut runtime, false, || has_lease_at(&invalid_root, "fp0"), || panic!("lease lookup must fail closed")).is_err());
        assert!(!runtime.recovered); assert!(!runtime.recovery_deferred);
    }

    #[test]
    fn native_nft_whitelist_and_explicit_trust_preserve_default_failure() {
        use serde_json::json;
        let base = json!({"chain":{"family":"inet","table":"external","name":"fwd","hook":"forward","policy":"accept"}});
        let rule = |expr| json!({"rule":{"family":"inet","table":"external","chain":"fwd","expr":expr}});
        let iface = |key, op, right| json!({"match":{"op":op,"left":{"meta":{"key":key}},"right":right}});
        for (expr, allowed) in [
            (vec![json!({"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"invalid"}}), json!({"drop":null})], true),
            (vec![json!({"match":{"op":"in","left":{"ct":{"key":"state"}},"right":{"set":["invalid"]}}}), json!({"drop":null})], true),
            (vec![iface("iifname", "==", json!("docker0")), json!({"drop":null})], true),
            (vec![iface("oifname", "==", json!({"set":["docker0","br-lan"]})), json!({"reject":null})], true),
            (vec![iface("iifname", "==", json!("fp*")), iface("oifname", "!=", json!("eth0")), json!({"drop":null})], true),
            (vec![iface("iifname", "==", json!("fp*")), json!({"drop":null})], false),
            (vec![iface("iifname", "==", json!("@interfaces")), json!({"drop":null})], false),
            (vec![json!({"match":{"op":"==","left":{"ct":{"key":"state"}},"right":{"set":["invalid","new"]}}}), json!({"drop":null})], false),
        ] {
            let ruleset = json!({"nftables":[base,rule(expr)]});
            assert_eq!(nft_check_forward(&ruleset, "fp0", "eth0").is_ok(), allowed);
        }
        let owned = json!({"nftables":[{"chain":{"family":"inet","table":"fluxpeer_other","name":"fwd","hook":"forward","policy":"drop"}}]});
        nft_check_forward(&owned, "fp0", "eth0").unwrap();
        let failure = nft_check_forward(&json!({"nftables":[{"chain":{"family":"inet","table":"fw4","name":"forward","hook":"forward","policy":"drop"}}]}), "fp0", "eth0");
        assert!(check_external(failure.clone(), false).unwrap_err().stderr.contains("firewall_trust_external=true"));
        check_external(failure, true).unwrap();
    }

    #[test]
    fn trust_config_reaches_real_firewall_setup_and_default_refuses_before_mutation() {
        let rules = serde_json::json!({"nftables":[{"chain":{"family":"inet","table":"fw4","name":"forward","hook":"forward","policy":"drop"}}]}).to_string();
        for trust in [false, true] {
            let dir = tempfile::tempdir().unwrap(); let mut host = Host { external_rules: Some(rules.clone()), ..Host::default() };
            let cfg: crate::Config = serde_json::from_value(serde_json::json!({"private_key":"00", "device_id":"test", "control_server":"http://example.invalid", "listen_port":0, "tun_name":"fp0", "prefix_len":24, "firewall_trust_external":trust})).unwrap();
            let policy = crate::ProviderPolicy::from_config(&cfg, false);
            let options = Options { trust_external: policy.trust_external, ..options() };
            assert_eq!(execute_with(&mut host, dir.path(), "nft", Operation::Up, ("wan0", "fp0"), &options).is_ok(), trust);
            assert_eq!(host.forwarding, trust); assert_eq!(host.tables.is_empty(), !trust);
            assert_eq!(dir.path().join(format!("{}.lease", instance("fp0").unwrap())).exists(), trust);
        }
    }

    #[test]
    fn detection_does_not_hide_permission_failures_and_unsupported_nft_is_absent() {
        for failure in [error(Some(1), "Permission denied"), error(Some(4), "xtables lock busy")] {
            let mut runner = Scripted::new(vec![Err(failure)]);
            assert!(detect_with(&mut runner, None).is_err()); assert_eq!(runner.commands.len(), 1);
        }
        for message in ["Protocol not supported", "Operation not supported", "nft: invalid option -- 'j'", "unrecognized option '-j'"] {
            let mut runner = Scripted::new(vec![Err(error(Some(1), message))]);
            iptables_check_nft(&mut runner, "fp0", "eth0").unwrap();
        }
        let mut runner = Scripted::new(vec![Err(error(Some(1), "Permission denied: Operation not supported"))]);
        assert!(iptables_check_nft(&mut runner, "fp0", "eth0").is_err());
    }

    #[test]
    fn trusted_external_policy_never_suppresses_inspection_errors_or_acquires_lease() {
        for backend in ["nft", "iptables"] {
            for reply in [Err(error(Some(1), "Permission denied")), Err(error(Some(2), "execution failed")),
                Ok("invalid JSON".into()), Ok(r#"{"unexpected":[]}"#.into())] {
                let dir = tempfile::tempdir().unwrap();
                let mut runner = Scripted::new(vec![reply]);
                let trusted = Options { trust_external: true, ..options() };
                assert!(execute_with(&mut runner, dir.path(), backend, Operation::Up, ("wan0", "fp0"), &trusted).is_err());
                assert_eq!(runner.commands, [vec!["nft", "-j", "list", "ruleset"]]);
                assert!(!has_lease_at(dir.path(), "fp0").unwrap());
            }
        }
        let rules = serde_json::json!({"nftables":[{"chain":{"family":"ip","table":"filter","name":"FORWARD","hook":"forward","policy":"drop"}}]}).to_string();
        let mut runner = Scripted::new(vec![Ok(rules), Err(error(Some(1), "Operation not permitted"))]);
        assert!(check_external(iptables_check_nft(&mut runner, "fp0", "wan0"), true).is_err());
        assert_eq!(runner.commands.len(), 2);
    }

    #[test]
    fn both_firewalls_keep_dual_family_guards_but_nat_only_overlay_family() {
        for (prefix, family, binary) in [("100.72.0.0/24", "ipv4", "iptables"), ("fd00::/64", "ipv6", "ip6tables")] {
            let mut host = Host::default();
            let id = instance("fp0").unwrap();
            iptables_with(&mut host, Operation::Up, "wan0", "fp0", &id, prefix).unwrap();
            let nat: Vec<_> = host.rules.iter().filter(|rule| rule.iter().any(|v| v == "MASQUERADE")).collect();
            assert_eq!(nat.len(), 1); assert_eq!(nat[0][0], binary);
            for bin in ["iptables", "ip6tables"] {
                assert!(host.rules.iter().any(|rule| rule[0] == bin && rule.iter().any(|v| v == "ACCEPT")));
                assert!(host.rules.iter().any(|rule| rule[0] == bin && rule.iter().any(|v| v == "DROP")));
            }
            nft_with(&mut host, Operation::Up, "wan0", "fp0", &id, prefix).unwrap();
            let script = host.scripts.last().unwrap();
            assert!(script.contains(&format!("meta nfproto {family} iifname \"fp0\" oifname \"wan0\" masquerade")));
            assert_eq!(script.matches("meta nfproto").count(), 1);
            assert!(script.contains("ct state established,related accept"));
            assert!(script.contains("ct state != { established, related } drop"));
        }
    }

    #[test]
    fn iptables_killswitch_uses_owned_chain_exact_arguments_and_waits_for_lock() {
        for bin in ["iptables", "ip6tables"] {
            let id = instance("custom0").unwrap();
            let tag = format!("{id}:killswitch");
            let chain = "FPKS_custom0";
            let mut replies = vec![Err(error(Some(1), "No chain/target/match by that name.")), Ok(String::new())];
            let mut expected = vec![vec![bin, "-w", "10", "-S", chain], vec![bin, "-w", "10", "-N", chain]];
            for rule in [
                vec![chain, "-i", "fp+", "-m", "comment", "--comment", &tag, "-j", "RETURN"],
                vec![chain, "-i", "custom0", "-m", "comment", "--comment", &tag, "-j", "RETURN"],
                vec![chain, "-m", "comment", "--comment", &tag, "-j", "DROP"],
            ] {
                replies.extend([Err(error(Some(1), "Bad rule")), Ok(String::new())]);
                for op in ["-C", "-A"] { expected.push([vec![bin, "-w", "10", op], rule.clone()].concat()); }
            }
            let jump = vec!["FORWARD", "-o", "wan0", "-m", "comment", "--comment", &tag, "-j", chain];
            // An existing jump below Docker must be promoted, not just found by -C.
            replies.extend([Ok(format!("-A FORWARD -j DOCKER-USER\n-A {}", jump.join(" "))), Ok(String::new())]);
            expected.push(vec![bin, "-w", "10", "-S", "FORWARD"]);
            expected.push([vec![bin, "-w", "10", "-I"], jump].concat());
            let mut runner = Scripted::new(replies);
            iptables_killswitch_on(&mut runner, bin, "wan0", "custom0", &id).unwrap();
            assert_eq!(runner.commands, expected);
        }
    }

    #[test]
    fn nft_up_preserves_killswitch_and_down_removes_only_its_instance() {
        let mut host = Host::default();
        let id = instance("custom0").unwrap();
        let guard = format!("{id}_forward_guard");
        nft_with(&mut host, Operation::KillswitchOn, "wan0", "custom0", &id, "").unwrap();
        let original = host.tables[&guard].clone();
        assert!(original.contains("iifname != \"fp*\" iifname != \"custom0\" drop"));
        nft_with(&mut host, Operation::Up, "wan0", "custom0", &id, "100.72.0.0/24").unwrap();
        assert_eq!(host.tables[&guard], original);
        host.tables.insert("foreign".into(), "keep".into());
        nft_with(&mut host, Operation::Down, "wan0", "custom0", &id, "").unwrap();
        assert_eq!(host.tables.len(), 1);
        assert_eq!(host.tables["foreign"], "keep");
    }

    #[test]
    fn instance_names_are_distinct_safe_and_reject_paths() {
        assert_ne!(instance("fp-0").unwrap(), instance("fp_0").unwrap());
        assert!(instance("../fp").is_err()); assert!(instance("a\"; drop").is_err());
        assert_eq!(instance("fp0").unwrap(), "fluxpeer_667030");
    }

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
            assert_eq!(runner.commands, [vec!["ip6tables", "-w", "10", "-t", "nat", "-C", "POSTROUTING", "-o", "wan0", "-j", "MASQUERADE"]]);
        }
        let mut runner = Scripted::new(vec![Err(error(Some(1), "Bad rule")), Ok("".into())]);
        iptables_ensure_with(&mut runner, "iptables", &["-t", "nat"], "-A", &rule).unwrap();
        assert_eq!(runner.commands[1], ["iptables", "-w", "10", "-t", "nat", "-A", "POSTROUTING", "-o", "wan0", "-j", "MASQUERADE"]);
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
            assert_eq!(runner.commands[0], ["iptables", "-w", "10", "-t", "nat", "-C", "POSTROUTING"]);
        }
        let mut runner = Scripted::new(vec![Ok("".into()), Ok("".into()), Err(error(Some(1), "Bad rule"))]);
        iptables_drain_with(&mut runner, "iptables", &[], &["FORWARD"]).unwrap();
        assert_eq!(runner.commands[1], ["iptables", "-w", "10", "-D", "FORWARD"]);
        let mut runner = Scripted::new(vec![Ok("".into()), Err(error(Some(4), "Permission denied"))]);
        assert!(iptables_drain_with(&mut runner, "iptables", &[], &["FORWARD"]).is_err());
    }
}
