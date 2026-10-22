// SPDX-License-Identifier: BSD-3-Clause
//! macOS provider NAT. Stable membership names own anchors, tokens and leases;
//! kernel-assigned utun names occur only inside the rules, never in journal keys.
use super::{apply, forwarding::State, ApplyError, Result};
use std::{fs, path::{Path, PathBuf}};

#[derive(serde::Serialize, serde::Deserialize)]
struct Owner { iface: String, token: Option<String>, acquiring: bool, retiring: bool }

#[cfg(target_os = "macos")]
fn root(base: &Path) -> Result<PathBuf> {
    use apply::Runner;
    let boot = apply::System.run(&["sysctl", "-n", "kern.bootsessionuuid"], None)?;
    boot_root(base, boot.trim())
}
fn boot_root(base: &Path, boot: &str) -> Result<PathBuf> {
    if boot.len() != 36 || boot.chars().enumerate().any(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c != '-' } else { !c.is_ascii_hexdigit() }) {
        return Err(error("invalid macOS boot session UUID"));
    }
    // PF tokens, rules and forwarding baselines are boot-local. Old on-disk
    // records must never release a new boot's token or restore its sysctls.
    Ok(base.join(boot.to_ascii_lowercase()))
}
#[cfg(target_os = "macos")]
pub(crate) fn up(iface: &str, tun: &str, phys: &str, cidr: &str) -> Result {
    up_with(&mut apply::System, &root(Path::new(BASE))?, iface, tun, phys, cidr)
}
#[cfg(target_os = "macos")]
pub(crate) fn down(iface: &str) -> Result { down_at(Path::new(BASE), iface) }
#[cfg(target_os = "macos")]
pub(crate) const BASE: &str = "/var/run/fluxpeer-pf";
#[cfg(target_os = "macos")]
pub(crate) fn down_at(base: &Path, iface: &str) -> Result {
    // Ordinary clients and test fixtures need neither PF commands nor a root
    // directory until a provider has actually acquired persistent resources.
    if !base.try_exists()? { return Ok(()); }
    down_with(&mut apply::System, &root(base)?, iface)
}

fn anchor(iface: &str) -> Result<String> { super::instance(iface)?; Ok(format!("com.apple/250.fluxpeer.{iface}")) }
fn path(root: &Path, iface: &str, suffix: &str) -> Result<PathBuf> { Ok(root.join(format!("{}.{suffix}", super::instance(iface)?))) }
fn error(message: impl Into<String>) -> ApplyError { ApplyError::new(&["pf", "ownership"], message) }
fn load(root: &Path, iface: &str) -> Result<Option<Owner>> {
    let Some(bytes) = crate::carriers::read_private(&path(root, iface, "pf.json")?)? else { return Ok(None); };
    let owner: Owner = serde_json::from_slice(&bytes).map_err(|e| error(format!("invalid PF journal: {e}")))?;
    if owner.iface != iface || owner.token.as_deref().is_some_and(|s| valid_token(s).is_err()) || (owner.acquiring && owner.token.is_some()) {
        return Err(error("invalid PF journal identity or token"));
    }
    Ok(Some(owner))
}
fn save(state: &State, root: &Path, owner: &Owner) -> Result {
    state.save(&path(root, &owner.iface, "pf.json")?, &serde_json::to_vec(owner).map_err(|e| error(e.to_string()))?)
}
fn remove(path: &Path) -> Result {
    match fs::remove_file(path) { Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, result => result? }
    if let Some(parent) = path.parent() { fs::File::open(parent)?.sync_all()?; }
    Ok(())
}
fn valid_token(value: &str) -> Result<&str> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || value.parse::<u64>().is_err() {
        return Err(error("invalid PF enable token"));
    }
    Ok(value)
}
fn token(output: &str) -> Result<String> {
    let mut found = None;
    for line in output.split_inclusive('\n') {
        let Some(value) = line.trim().strip_prefix("Token :") else { continue; };
        if !line.ends_with('\n') { return Err(error("incomplete PF enable token receipt")); }
        if found.is_some() { return Err(error("multiple tokens in PF enable receipt")); }
        found = Some(valid_token(value.trim())?.to_owned());
    }
    found.ok_or_else(|| error("PF enable receipt has no token; ownership is uncertain, retain journal for recovery"))
}

fn recover_token(state: &State, root: &Path, owner: &mut Owner) -> Result {
    if !owner.acquiring { return Ok(()); }
    // System opens the receipt before spawning pfctl. An absent receipt means
    // no command ran. An empty/partial receipt is ambiguous: never acquire a
    // second reference or guess ownership from another process's references.
    owner.token = match crate::carriers::read_private(&path(root, &owner.iface, "enable.log")?)? {
        Some(bytes) => Some(token(std::str::from_utf8(&bytes).map_err(|e| error(e.to_string()))?)?),
        None => None,
    };
    owner.acquiring = false;
    save(state, root, owner)
}
fn hooks(runner: &mut impl apply::Runner) -> Result {
    for (flag, expected) in [("-sn", "nat-anchor \"com.apple/*\""), ("-sr", "anchor \"com.apple/*\"")] {
        let rules = runner.run(&["pfctl", flag], None)?;
        if !rules.lines().any(|line| { let line = line.trim(); line == expected || line.strip_suffix(" all") == Some(expected) }) {
            return Err(error(format!("missing unconditional {expected} hook in live main ruleset; configure PF externally")));
        }
    }
    Ok(())
}
fn rules(iface: &str, tun: &str, phys: &str, cidr: &str) -> Result<String> {
    super::instance(tun)?; super::instance(phys)?;
    let tag = super::instance(iface)?;
    let (address, prefix) = cidr.split_once('/').ok_or_else(|| error("invalid IPv4 overlay CIDR"))?;
    let address = address.parse::<std::net::Ipv4Addr>().map_err(|e| error(e.to_string()))?;
    let prefix = prefix.parse::<u8>().map_err(|e| error(e.to_string()))?;
    if prefix > 32 || tun == phys { return Err(error("invalid overlay prefix or physical interface equals TUN")); }
    let cidr = format!("{address}/{prefix}");
    Ok(format!("nat on {phys} inet from {cidr} to any tagged \"{tag}\" -> ({phys})\n\
pass in quick on {tun} inet from {cidr} to any tag \"{tag}\" keep state\n\
pass out quick on {phys} inet tagged \"{tag}\" keep state\n"))
}
fn up_with(runner: &mut impl apply::Runner, root: &Path, iface: &str, tun: &str, phys: &str, cidr: &str) -> Result {
    let anchor = anchor(iface)?;
    let rules = rules(iface, tun, phys, cidr)?;
    let state = State::lock(root)?;
    if let Some(mut owner) = load(root, iface)? && owner.retiring { cleanup(runner, &state, root, &mut owner)?; }
    hooks(runner)?;
    let mut owner = match load(root, iface)? {
        Some(owner) => owner,
        None => {
            if path(root, iface, "lease")?.try_exists()? { return Err(error("forwarding lease exists without PF ownership journal")); }
            for flag in ["-sn", "-sr"] {
                if !runner.run(&["pfctl", "-a", &anchor, flag], None)?.trim().is_empty() {
                    return Err(error("unowned rules already occupy this PF anchor"));
                }
            }
            let owner = Owner { iface: iface.into(), token: None, acquiring: false, retiring: false };
            save(&state, root, &owner)?;
            owner
        }
    };
    recover_token(&state, root, &mut owner)?;
    state.acquire_macos(runner, &super::instance(iface)?)?;
    if owner.token.is_none() {
        let receipt = path(root, iface, "enable.log")?;
        remove(&receipt)?;
        owner.acquiring = true;
        save(&state, root, &owner)?;
        let enabled = runner.run_recorded(&["pfctl", "-E"], &receipt);
        if let Err(e) = enabled {
            // Only a rejected acquire ioctl proves that no token was acquired.
            // A local IO error may occur AFTER acquisition (for example fsync).
            // Import a complete receipt even when command handling failed.
            if e.exit_code.is_some() && e.kind != std::io::ErrorKind::TimedOut && e.stderr.contains("DIOCSTARTREF") {
                owner.acquiring = false;
                save(&state, root, &owner)?;
                return Err(e);
            }
            return apply::all([Err(e), recover_token(&state, root, &mut owner)]);
        }
        recover_token(&state, root, &mut owner)?;
        if owner.token.is_none() { return Err(error("successful PF enable did not produce a receipt")); }
    }
    runner.run(&["pfctl", "-a", &anchor, "-f", "-"], Some(&rules))?;
    Ok(())
}
fn cleanup(runner: &mut impl apply::Runner, state: &State, root: &Path, owner: &mut Owner) -> Result {
    owner.retiring = true; save(state, root, owner)?;
    let anchor = anchor(&owner.iface)?;
    // Never use -F all/states: PF's connection state is shared with other apps.
    let nat = runner.run(&["pfctl", "-a", &anchor, "-F", "nat"], None).map(|_| ());
    let filter = runner.run(&["pfctl", "-a", &anchor, "-F", "rules"], None).map(|_| ());
    apply::all([nat, filter])?;
    state.release_macos(runner, &super::instance(&owner.iface)?)?;
    recover_token(state, root, owner)?;
    if let Some(token) = &owner.token {
        match runner.run(&["pfctl", "-X", token], None) {
            // A crash after -X but before journal removal is safe to retry.
            // Only Apple's specific invalid-token error means already released.
            Err(e) if e.exit_code.is_some() && e.stderr.lines().any(|line| line.trim() == "pf: token invalid") => {},
            result => { result?; },
        }
    }
    // Clear token ownership before removing the receipt. A crash here must not
    // let an old receipt be imported as a newly acquired reference.
    owner.token = None; owner.acquiring = false; save(state, root, owner)?;
    remove(&path(root, &owner.iface, "enable.log")?)?;
    remove(&path(root, &owner.iface, "pf.json")?)
}
fn down_with(runner: &mut impl apply::Runner, root: &Path, iface: &str) -> Result {
    anchor(iface)?;
    let state = State::lock(root)?;
    match load(root, iface)? {
        Some(mut owner) => cleanup(runner, &state, root, &mut owner),
        None if path(root, iface, "lease")?.try_exists()? => Err(error("forwarding lease exists without PF ownership journal")),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "pf_tests.rs"]
mod tests;
