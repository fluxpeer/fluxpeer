//! Cross-platform route + DNS management, including full-tunnel (exit-node) setup.
//! Modeled on the `fp-route` crate but run directly — the node is root, so it needs no
//! privileged-helper hop. `ip`/`resolvectl` on Linux, `route`/`scutil` on macOS.

use crate::apply::{self, ApplyError, Result};

#[cfg(any(windows, test))]
pub(crate) mod windows;

/// Normalize a host or CIDR to a CIDR (`1.2.3.4` → `1.2.3.4/32`).
fn cidr(s: &str) -> String {
    if s.contains('/') {
        s.to_string()
    } else if s.contains(':') {
        format!("{s}/128")
    } else {
        format!("{s}/32")
    }
}

/// Connected route for `cidr` over the tun device. A default route (`0.0.0.0/0` /
/// `::/0`) is NEVER installed raw — it would clobber the physical default; full-
/// tunnel uses the split-default in [`exit_up`]. Returns Skipped when an optional
/// route was skipped, so reconciliation can retry it without claiming ownership.
pub(crate) fn route_replace(cidr: &str, dev: &str) -> Result<apply::RouteOutcome> {
    optional_route_result(current_os(), cidr, route_change_with(current_os(), cidr, dev, true, &mut apply::System))
}

pub(crate) fn route_del(cidr: &str, dev: &str) -> Result {
    optional_route_result(current_os(), cidr, route_change_with(current_os(), cidr, dev, false, &mut apply::System)).map(|_| ())
}

fn optional_route_result(_os: RouteOs, cidr: &str, result: Result) -> Result<apply::RouteOutcome> {
    match result {
        Err(error) if cidr.contains(':') && apply::ipv6_unavailable(&error) => {
                Ok(apply::RouteOutcome::Skipped(error))
            }
        result => result.map(|()| apply::RouteOutcome::Installed),
    }
}

fn route_change_with(os: RouteOs, cidr: &str, dev: &str, add: bool, runner: &mut impl apply::Runner) -> Result {
    if crate::control::is_default_prefix(cidr) { return Ok(()); }
    if os == RouteOs::Windows {
        #[cfg(windows)]
        return if add { windows::add(cidr, dev, None) } else { windows::remove(cidr, dev) }.map_err(ApplyError::from);
        #[cfg(not(windows))]
        return Err(ApplyError::io(&["route", cidr, dev], std::io::Error::new(std::io::ErrorKind::Unsupported, "IP Helper requires Windows")));
    }
    if os == RouteOs::Macos {
        let family = if cidr.contains(':') { "-inet6" } else { "-inet" };
        missing_is_removed(runner.run(&["route", "-n", "delete", family, "-net", cidr], None).map(|_| ()))?;
        if add { runner.run(&["route", "-n", "add", family, "-net", cidr, "-interface", dev], None)?; }
        Ok(())
    } else {
        let result = runner.run(&["ip", if cidr.contains(':') { "-6" } else { "-4" }, "route", if add { "replace" } else { "del" }, cidr, "dev", dev], None).map(|_| ());
        if add { result } else { missing_is_removed(result) }
    }
}

fn missing_is_removed(result: Result) -> Result {
    match result { Err(e) if e.exit_code.is_some() && e.missing() => Ok(()), result => result }
}

/// A bypass route: `dst` routes via the original physical `gateway` on `phys`
/// instead of the tunnel. The explicit device is REQUIRED — the split-default is
/// already installed, so a `via`-only route would resolve the gateway back through
/// the tun and loop. More specific than `0.0.0.0/1`, so it wins (split-exclude).
pub(crate) fn bypass_add(dst: &str, gateway: &str, phys: &str) -> Result<bool> {
    let v6 = dst.parse::<fluxpeer_sdk::prefix::IpPrefix>().is_ok_and(|p| p.network().is_ipv6());
    let v6_route = if v6 { physical_v6_route()? } else { None };
    let (gateway, phys) = if v6 {
        let Some((gateway, phys)) = v6_route.as_ref() else {
            tracing::warn!(dst, "no IPv6 physical default; carrier bypass not needed until IPv6 is available");
            return Ok(false);
        };
        (gateway.as_str(), phys.as_str())
    } else { (gateway, phys) };
    if current_os() == RouteOs::Windows {
        #[cfg(windows)]
        { windows::add(&cidr(dst), phys, Some(gateway))?; return Ok(true); }
    }
    if current_os() == RouteOs::Macos {
        // Match the existing IPv4 replacement behavior, with the right family.
        bypass_del(dst)?;
    }
    if let Some(command) = bypass_cmd(current_os(), dst, Some((gateway, phys))) {
        run_route_command(&command)?;
        return Ok(true);
    }
    Err(ApplyError::new(&["bypass", dst], "unsupported platform"))
}

pub(crate) fn bypass_del(dst: &str) -> Result {
    if current_os() == RouteOs::Windows {
        #[cfg(windows)]
        return windows::remove_bypass(&cidr(dst)).map_err(ApplyError::from);
    }
    if let Some(command) = bypass_cmd(current_os(), dst, None) {
        missing_is_removed(run_route_command(&command).map_err(ApplyError::from))?;
    }
    Ok(())
}

fn bypass_cmd(os: RouteOs, dst: &str, via: Option<(&str, &str)>) -> Option<Vec<String>> {
    let d = cidr(dst);
    let v6 = dst.parse::<fluxpeer_sdk::prefix::IpPrefix>().is_ok_and(|p| p.network().is_ipv6());
    match (os, via) {
        (RouteOs::Linux, Some((gateway, phys))) => Some(argv(&["ip", if v6 { "-6" } else { "-4" }, "route", "replace", &d, "via", gateway, "dev", phys])),
        (RouteOs::Linux, None) => Some(argv(&["ip", if v6 { "-6" } else { "-4" }, "route", "del", &d])),
        (RouteOs::Macos, Some((gateway, _))) => Some(argv(&["route", "-n", "add", if v6 { "-inet6" } else { "-inet" }, "-net", &d, gateway])),
        (RouteOs::Macos, None) => Some(argv(&["route", "-n", "delete", if v6 { "-inet6" } else { "-inet" }, "-net", &d])),
        _ => None,
    }
}

/// IPv6 carriers must bypass through the IPv6 physical gateway, never through
/// the IPv4 gateway. Query before installing the guard's /1 routes.
pub(crate) fn physical_v6_route() -> Result<Option<(String, String)>> {
    if current_os() == RouteOs::Windows {
        #[cfg(windows)]
        return windows::default_route(true).map_err(ApplyError::from);
    }
    let command: &[&str] = match current_os() {
        RouteOs::Linux => &["ip", "-6", "route", "show", "default"],
        RouteOs::Macos => &["route", "-n", "get", "-inet6", "default"],
        RouteOs::Other | RouteOs::Windows => return Ok(None),
    };
    match apply::output(command) {
        Ok(output) => Ok(parse_physical_v6_route(current_os(), &output)),
        Err(e) if apply::ipv6_unavailable(&e) => { tracing::warn!(%e, "IPv6 physical route unavailable"); Ok(None) },
        Err(e) => Err(e),
    }
}

fn parse_physical_v6_route(os: RouteOs, output: &str) -> Option<(String, String)> {
    if os == RouteOs::Macos {
        let field = |name: &str| output.lines().find_map(|l| l.trim().strip_prefix(name).map(|v| v.trim().to_string()));
        Some((field("gateway:")?, field("interface:")?))
    } else {
        let parts: Vec<_> = output.lines().next()?.split_whitespace().collect();
        let after = |word: &str| parts.iter().position(|v| *v == word).and_then(|i| parts.get(i + 1)).map(|s| s.to_string());
        Some((after("via")?, after("dev")?))
    }
}

/// The original physical default gateway (before fp takes over) — needed so bypass
/// routes point back at the real next hop.
pub(crate) fn default_gateway() -> Result<Option<String>> {
    let output = physical_default()?;
    Ok(default_field(&output, "gateway:", "via"))
}

fn physical_default() -> Result<String> {
    #[cfg(target_os = "macos")]
    { apply::output(&["route", "-n", "get", "default"]) }
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    { apply::output(&["ip", "route", "show", "default"]) }
    #[cfg(windows)]
    { Ok(windows::default_route(false)?.map(|(gateway, dev)| format!("default via {gateway} dev {dev}")).unwrap_or_default()) }
}

fn default_field(output: &str, _mac_field: &str, _linux_field: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    { output.lines().find_map(|l| l.trim().strip_prefix(_mac_field).map(|g| g.trim().to_string())) }
    #[cfg(not(target_os = "macos"))]
    {
        let parts: Vec<_> = output.split_whitespace().collect();
        parts.iter().position(|w| *w == _linux_field).and_then(|i| parts.get(i + 1)).map(|v| v.to_string())
    }
}

/// Connected destinations already have a more-specific route. A failed lookup
/// is not evidence of an on-link destination and must prevent a false full-tunnel UP.
pub(crate) fn needs_bypass(dst: &str) -> Result<bool> {
    let _ip = dst.split('/').next().unwrap_or(dst);
    #[cfg(target_os = "macos")]
    { Ok(true) }
    #[cfg(windows)]
    { windows::needs_bypass(&cidr(dst)).map_err(ApplyError::from) }
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    {
        if _ip.contains(':') && physical_v6_route()?.is_none() { return Ok(false); }
        Ok(apply::output(&["ip", if _ip.contains(':') { "-6" } else { "-4" }, "route", "get", _ip])?.contains(" via ")) }
}

/// The physical egress interface (the default route's device) — for exit-node NAT.
pub(crate) fn physical_iface() -> Result<Option<String>> {
    Ok(default_field(&physical_default()?, "interface:", "dev"))
}

/// Bring up full-tunnel (exit node): the `0.0.0.0/1` + `128.0.0.0/1` split-default
/// over the tun (overrides the physical default WITHOUT deleting it — the wg-quick
/// trick) and bypass routes for the carrier + excluded subnets via `gateway`.
/// DNS is applied independently and never causes these routes to be rolled back.
/// Returns whether IPv6 egress was blocked (see [`v6_block_up`]) so the teardown
/// removes exactly what we installed.
#[derive(Default)]
pub(crate) struct ExitProgress {
    bypass: Vec<String>,
    defaults: Vec<String>,
    v6_blocked: bool,
    v6_cleanup: Vec<Vec<String>>,
}

#[derive(Debug)]
enum ExitEffect<'a> {
    BypassAdd(&'a str), BypassDel(&'a str), GuardUp(&'a mut Vec<Vec<String>>), GuardDown(&'a mut Vec<Vec<String>>),
    DefaultAdd(&'a str), DefaultDel(&'a str),
}

fn cleanup_exit_with(progress: &mut ExitProgress, effect: &mut impl FnMut(ExitEffect<'_>) -> Result<bool>) -> Result {
    let mut errors = Vec::new();
    progress.defaults.retain(|p| match effect(ExitEffect::DefaultDel(p)) {
        Ok(_) => false, Err(e) => { errors.push(Err(e)); true }
    });
    if !progress.v6_cleanup.is_empty() {
        match effect(ExitEffect::GuardDown(&mut progress.v6_cleanup)) { Ok(_) => progress.v6_blocked = false, Err(e) => errors.push(Err(e)) }
    }
    // Keep carrier/control bypasses until every redirect is gone. Otherwise a
    // failed default-route removal could strand the next control poll in the TUN.
    if progress.defaults.is_empty() && progress.v6_cleanup.is_empty() {
        progress.bypass.retain(|p| match effect(ExitEffect::BypassDel(p)) {
            Ok(_) => false, Err(e) => { errors.push(Err(e)); true }
        });
    }
    apply::all(errors)
}

fn exit_up_with(
    progress: &mut ExitProgress, bypass: &[String],
    mut effect: impl FnMut(ExitEffect<'_>) -> Result<bool>,
) -> Result<bool> {
    cleanup_exit_with(progress, &mut effect)?;
    let result: Result = (|| {
        for b in bypass { if effect(ExitEffect::BypassAdd(b))? { progress.bypass.push(b.clone()); } }
        progress.v6_blocked = effect(ExitEffect::GuardUp(&mut progress.v6_cleanup))?;
        for p in ["0.0.0.0/1", "128.0.0.0/1"] {
            effect(ExitEffect::DefaultAdd(p))?;
            progress.defaults.push(p.into());
        }
        Ok(())
    })();
    if let Err(mut error) = result {
        if let Err(cleanup) = cleanup_exit_with(progress, &mut effect) {
            error.stderr.push_str(&format!("; rollback: {cleanup}"));
        }
        return Err(error);
    }
    Ok(progress.v6_blocked)
}

fn exit_effect(dev: &str, gateway: &str, phys: &str, effect: ExitEffect<'_>) -> Result<bool> {
    match effect {
        ExitEffect::BypassAdd(b) => return bypass_add(b, gateway, phys),
        ExitEffect::BypassDel(b) => bypass_del(b)?,
        ExitEffect::GuardUp(pending) => return v6_block_up(dev, pending).map_err(ApplyError::from),
        ExitEffect::GuardDown(pending) => v6_cleanup_with(pending, run_route_command)?,
        ExitEffect::DefaultAdd(p) => { route_replace(p, dev)?; },
        ExitEffect::DefaultDel(p) => route_del(p, dev)?,
    }
    Ok(false)
}

pub(crate) fn cleanup_exit(dev: &str, progress: &mut ExitProgress) -> Result {
    cleanup_exit_with(progress, &mut |e| exit_effect(dev, "", "", e))
}

pub(crate) fn exit_up(dev: &str, gateway: &str, phys: &str, bypass: &[String], progress: &mut ExitProgress) -> Result<bool> {
    let blocked = exit_up_with(progress, bypass, |e| exit_effect(dev, gateway, phys, e))?;
    tracing::info!(dev, gateway, phys, v6_blocked = blocked, "exit-node (full-tunnel) routes UP");
    Ok(blocked)
}

pub(crate) fn exit_down(dev: &str, progress: &mut ExitProgress) -> Result {
    cleanup_exit(dev, progress)?;
    tracing::info!(dev, "exit-node (full-tunnel) DOWN");
    Ok(())
}

/// The route OS family, for command generation (unit-tested per variant).
/// Variants for other platforms look dead in a single-OS build — they exist
/// for the cross-platform tests.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RouteOs {
    Linux,
    Macos,
    Windows,
    Other,
}

pub(crate) const fn current_os() -> RouteOs {
    #[cfg(target_os = "linux")]
    {
        RouteOs::Linux
    }
    #[cfg(target_os = "macos")]
    {
        RouteOs::Macos
    }
    #[cfg(windows)]
    { RouteOs::Windows }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        RouteOs::Other
    }
}

/// The two halves of IPv6 space — the v6 counterpart of the `0.0.0.0/1` +
/// `128.0.0.0/1` split-default trick (covers `::/0` without touching any
/// pre-existing v6 default route).
const V6_HALVES: [&str; 2] = ["::/1", "8000::/1"];

/// Commands that BLOCK all IPv6 egress in full-tunnel (AD-3). Linux installs
/// ordinary routes into the TUN (unsupported IPv6 packets are dropped); macOS uses
/// RTF_REJECT routes tied to the tun. Neither enables IPv6 exit forwarding.
/// Use add, never replace, so a conflicting pre-existing route fails visibly.
fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

fn v6_block_cmds(os: RouteOs, dev: &str) -> Vec<Vec<String>> {
    match os {
        RouteOs::Linux => V6_HALVES
            .iter()
            .map(|p| argv(&["ip", "-6", "route", "add", *p, "dev", dev, "metric", "42760"]))
            .collect(),
        RouteOs::Macos => V6_HALVES
            .iter()
            .map(|p| argv(&["route", "-n", "add", "-inet6", "-net", *p, "-reject", "-interface", dev]))
            .collect(),
        RouteOs::Windows => V6_HALVES.iter().map(|p| argv(&["windows-route", "add", p, dev])).collect(),
        RouteOs::Other => Vec::new(),
    }
}

/// Commands that REMOVE the block installed by [`v6_block_cmds`].
fn v6_unblock_cmds(os: RouteOs, dev: &str) -> Vec<Vec<String>> {
    match os {
        RouteOs::Linux => V6_HALVES
            .iter()
            .map(|p| argv(&["ip", "-6", "route", "del", *p, "dev", dev, "metric", "42760"]))
            .collect(),
        RouteOs::Macos => V6_HALVES
            .iter()
            .map(|p| argv(&["route", "-n", "delete", "-inet6", "-net", *p, "-reject", "-interface", dev]))
            .collect(),
        RouteOs::Windows => V6_HALVES.iter().map(|p| argv(&["windows-route", "del", p, dev])).collect(),
        RouteOs::Other => Vec::new(),
    }
}

/// Remove only the previous implementation's dedicated unreachable routes.
/// Linux attaches unreachable routes to lo, regardless of the supplied TUN.
fn v6_legacy_cleanup_cmds(os: RouteOs) -> Vec<Vec<String>> {
    if os != RouteOs::Linux { return Vec::new(); }
    V6_HALVES.iter().map(|p| argv(&["ip", "-6", "route", "del", "unreachable", p, "metric", "42760"])).collect()
}

fn run_route_command(c: &[String]) -> std::io::Result<()> {
    #[cfg(windows)]
    if let [kind, operation, prefix, dev] = c && kind == "windows-route" {
        return match operation.as_str() {
            "add" => windows::add(prefix, dev, None), "del" => windows::remove(prefix, dev),
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown route operation")),
        };
    }
    let refs: Vec<_> = c.iter().map(String::as_str).collect();
    apply::run(&refs).map_err(|mut error| {
        error.kind = if error.exit_code.is_none() { error.kind }
        else if error.missing() { std::io::ErrorKind::NotFound }
        else if error.stderr.contains("File exists") { std::io::ErrorKind::AlreadyExists }
        else if error.stderr.contains("Address family not supported") || error.stderr.contains("IPv6 is disabled") { std::io::ErrorKind::Unsupported }
        else { std::io::ErrorKind::Other };
        error.into()
    })
}

#[cfg(test)]
fn v6_unblock_with(cmds: &[Vec<String>], mut run: impl FnMut(&[String]) -> std::io::Result<()>) -> std::io::Result<()> {
    let mut first = None;
    for command in cmds {
        if let Err(error) = run(command) {
            tracing::warn!(%error, "IPv6 guard teardown failed");
            if first.is_none() { first = Some(error); }
        }
    }
    first.map_or(Ok(()), Err)
}

/// Roll back only additions that succeeded. Never delete an existing ordinary
/// route after EEXIST; missing legacy unreachable routes are expected on upgrade.
#[cfg(test)]
fn v6_block_with(os: RouteOs, dev: &str, run: impl FnMut(&[String]) -> std::io::Result<()>) -> std::io::Result<bool> {
    v6_block_tracked(os, dev, &mut Vec::new(), run)
}

fn v6_cleanup_with(pending: &mut Vec<Vec<String>>, mut run: impl FnMut(&[String]) -> std::io::Result<()>) -> std::io::Result<()> {
    let mut first = None;
    pending.retain(|command| match run(command) {
        Ok(()) => false,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH)
            || error.get_ref().and_then(|e| e.downcast_ref::<ApplyError>()).is_some_and(|e| e.exit_code.is_some() && e.missing()) => false,
        Err(error) => { if first.is_none() { first = Some(error); } true }
    });
    first.map_or(Ok(()), Err)
}

fn v6_block_tracked(os: RouteOs, dev: &str, pending: &mut Vec<Vec<String>>, mut run: impl FnMut(&[String]) -> std::io::Result<()>) -> std::io::Result<bool> {
    v6_cleanup_with(pending, &mut run)?;
    for command in v6_legacy_cleanup_cmds(os) {
        if let Err(error) = run(&command)
            && error.kind() != std::io::ErrorKind::NotFound && error.raw_os_error() != Some(libc::ESRCH) { return Err(error); }
    }
    for (command, undo) in v6_block_cmds(os, dev).into_iter().zip(v6_unblock_cmds(os, dev)) {
        if let Err(error) = run(&command) {
            if let Err(rollback) = v6_cleanup_with(pending, &mut run) {
                tracing::error!(%rollback, "IPv6 block rollback failed; cleanup retained for retry");
            }
            return Err(error);
        }
        pending.push(undo);
    }
    Ok(!pending.is_empty())
}

fn v6_guard_result(result: std::io::Result<bool>) -> std::io::Result<bool> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
            tracing::warn!(%error, "IPv6 is disabled or unavailable; continuing IPv4 full-tunnel");
            Ok(false)
        }
        result => result,
    }
}

fn v6_block_up(dev: &str, pending: &mut Vec<Vec<String>>) -> std::io::Result<bool> {
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6").is_ok_and(|v| v.trim() == "1") {
        tracing::warn!("IPv6 is disabled; continuing IPv4 full-tunnel");
        return Ok(false);
    }
    let result = v6_block_tracked(current_os(), dev, pending, run_route_command);
    let blocked = if pending.is_empty() { v6_guard_result(result)? } else { result? };
    if blocked { tracing::info!("IPv6 egress blocked in full-tunnel (not supported yet)"); }
    Ok(blocked)
}

/// Provider forwarding and NAT; PF ownership uses the stable membership iface.
pub(crate) fn exit_gateway_up(phys: &str, tun: &str, overlay_cidr: &str, _trust_external: bool, _backend: Option<&dyn crate::firewall::Firewall>, _iface: &str) -> Result {
    #[cfg(target_os = "linux")]
    {
        _backend.ok_or_else(|| ApplyError::new(&["firewall", "up"], "missing selected backend"))?.up(phys, tun, &crate::firewall::Options { overlay_cidr: overlay_cidr.into(), trust_external: _trust_external })?;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = phys;
        win_ps(&format!("Set-NetIPInterface -InterfaceAlias '{tun}' -Forwarding Enabled"))?;
        win_ps("Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled")?;
        win_ps("Start-Service winnat")?;
        win_ps("Get-NetNat -Name fluxpeer-exit -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false")?;
        win_ps(&format!("New-NetNat -Name fluxpeer-exit -InternalIPInterfaceAddressPrefix '{overlay_cidr}'"))?;
    }
    #[cfg(target_os = "macos")]
    { crate::firewall::pf::up(_iface, tun, phys, overlay_cidr)?; }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    { Err(ApplyError::new(&["exit-gateway", phys, tun, overlay_cidr], "unsupported platform")) }
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Ok(())
}

#[cfg(target_os = "windows")]
fn win_ps(script: &str) -> Result {
    apply::run(&["powershell", "-NoProfile", "-Command", &format!("$ErrorActionPreference = 'Stop'; {script}")])
}

pub(crate) fn exit_gateway_down(phys: &str, tun: &str, _backend: Option<&dyn crate::firewall::Firewall>, _iface: &str) -> Result {
    #[cfg(target_os = "linux")]
    { _backend.ok_or_else(|| ApplyError::new(&["firewall", "down"], "missing selected backend"))?.down(phys, tun)?; }
    #[cfg(target_os = "windows")]
    {
        let _ = (phys, tun);
        win_ps("Get-NetNat -Name fluxpeer-exit -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false")?;
    }
    #[cfg(target_os = "macos")]
    { let _ = (phys, tun); crate::firewall::pf::down(_iface)?; }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    let _ = (phys, tun);
    Ok(())
}

pub(crate) fn set_dns(dev: &str, dns: &str, full_tunnel: bool) -> Result {
    if dns.split_whitespace().next().is_none() || dns.split_whitespace().any(|s| s.parse::<std::net::IpAddr>().is_err()) {
        return Err(ApplyError::new(&["DNS", "set"], "DNS servers must be IP addresses"));
    }
    #[cfg(any(target_os = "macos", windows))]
    let _ = full_tunnel;
    #[cfg(target_os = "macos")]
    { apply::input(&["scutil"], &format!("d.init\nd.add ServerAddresses * {dns}\nset State:/Network/Service/fluxpeer-{dev}/DNS\nquit\n"))?; }
    #[cfg(all(unix, not(target_os = "macos")))]
    crate::dns::detect_for_iface(Some(dev)).set_mode(dns, full_tunnel)?;
    #[cfg(windows)]
    {
        let servers = dns.split_whitespace().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(",");
        win_ps(&format!("Set-DnsClientServerAddress -InterfaceAlias '{dev}' -ServerAddresses {servers}"))?;
    }
    Ok(())
}

pub(crate) fn verify_dns_file(dev: &str) -> Result {
    #[cfg(all(unix, not(target_os = "macos")))]
    { crate::dns::detect_for_iface(Some(dev)).verify_file() }
    #[cfg(any(target_os = "macos", windows))]
    { let _ = dev; Ok(()) }
}

pub(crate) fn dns_restore_pending(dev: &str) -> Result<bool> {
    #[cfg(all(unix, not(target_os = "macos")))]
    { crate::dns::detect_for_iface(Some(dev)).owned() }
    #[cfg(any(target_os = "macos", windows))]
    { let _ = dev; Ok(false) }
}

pub(crate) fn reset_dns(dev: &str) -> Result {
    #[cfg(target_os = "macos")]
    { apply::input(&["scutil"], &format!("remove State:/Network/Service/fluxpeer-{dev}/DNS\nquit\n"))?; }
    #[cfg(all(unix, not(target_os = "macos")))]
    crate::dns::detect_for_iface(Some(dev)).clear()?;
    #[cfg(windows)]
    win_ps(&format!("Set-DnsClientServerAddress -InterfaceAlias '{dev}' -ResetServerAddresses"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_ipv6_route_waits_sixty_seconds_or_new_epoch_without_churning() {
        use apply::test_support::{Scripted, error};
        let desired = std::collections::HashSet::from(["fd00::/64".to_string()]);
        let mut state = apply::Routes::default();
        let unavailable = || Err(error(Some(2), "IPv6 is disabled"));
        let mut runner = Scripted::new(vec![unavailable(), unavailable(), Ok(String::new())]);
        let now = std::time::Instant::now();
        for (epoch, seconds, commands, installed) in [(42,0,1,false), (42,2,1,false), (42,59,1,false), (42,60,2,false), (43,61,3,true), (43,62,3,true)] {
            apply::sync_routes(&mut state, &desired, (epoch, now + std::time::Duration::from_secs(seconds)), |prefix| optional_route_result(RouteOs::Linux, prefix,
                route_change_with(RouteOs::Linux, prefix, "fp0", true, &mut runner)), |_| Ok(())).unwrap();
            assert_eq!(state.installed.contains("fd00::/64"), installed);
            assert_eq!(runner.commands.len(), commands);
        }
        assert!(runner.commands.iter().all(|c| c == &["ip", "-6", "route", "replace", "fd00::/64", "dev", "fp0"]));
    }

    #[tokio::test]
    async fn resolved_hostname_bypasses_cover_all_ips_and_failure_is_not_partial_success() {
        let candidates = crate::resolve_bypass_candidates(vec!["control.example".into(), "relay.example".into()], |_| {
            std::future::ready(Ok(vec!["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()]))
        }).await.unwrap();
        assert_eq!(candidates, ["192.0.2.2", "2001:db8::2"]);
        assert!(crate::resolve_bypass_candidates(vec!["192.0.2.2".into(), "missing.example".into()], |_| {
            std::future::ready(Err(std::io::Error::other("resolver offline")))
        }).await.is_err());
    }

    #[test]
    fn route_argv_and_optional_ipv6_failure_do_not_hide_ipv4_errors() {
        use apply::test_support::{Scripted, error};
        let mut runner = Scripted::new(vec![Err(error(Some(2), "Address family not supported"))]);
        let result = route_change_with(RouteOs::Linux, "fd00::/64", "fp0", true, &mut runner);
        optional_route_result(RouteOs::Linux, "fd00::/64", result).unwrap();
        assert_eq!(runner.commands[0], ["ip", "-6", "route", "replace", "fd00::/64", "dev", "fp0"]);
        let mut runner = Scripted::new(vec![Err(error(Some(2), "Operation not permitted"))]);
        let result = route_change_with(RouteOs::Linux, "10.0.0.0/8", "fp0", true, &mut runner);
        assert!(optional_route_result(RouteOs::Linux, "10.0.0.0/8", result).is_err());
        assert_eq!(runner.commands[0], ["ip", "-4", "route", "replace", "10.0.0.0/8", "dev", "fp0"]);
        let mut runner = Scripted::new(vec![]);
        let result = route_change_with(RouteOs::Windows, "10.0.0.0/8", "fp0", true, &mut runner);
        #[cfg(not(windows))]
        assert_eq!(result.as_ref().unwrap_err().kind, std::io::ErrorKind::Unsupported);
        assert!(optional_route_result(RouteOs::Windows, "10.0.0.0/8", result).is_err());
        assert!(runner.commands.is_empty());
    }

    #[test]
    fn failed_default_removal_keeps_carrier_bypass_until_retry() {
        let mut progress = ExitProgress {
            bypass: vec!["192.0.2.1".into()], defaults: vec!["0.0.0.0/1".into()], ..Default::default()
        };
        assert!(cleanup_exit_with(&mut progress, &mut |effect| match effect {
            ExitEffect::DefaultDel(_) => Err(ApplyError::new(&["ip", "route", "del"], "permission denied")),
            ExitEffect::BypassDel(_) => panic!("carrier must remain reachable until default is gone"),
            _ => Ok(false),
        }).is_err());
        assert_eq!(progress.bypass.len(), 1);
        let mut calls = Vec::new();
        cleanup_exit_with(&mut progress, &mut |effect| { calls.push(format!("{effect:?}")); Ok(false) }).unwrap();
        assert!(calls[0].starts_with("DefaultDel"));
        assert!(calls[1].starts_with("BypassDel"));
        assert!(progress.defaults.is_empty());
        assert!(progress.bypass.is_empty());
    }

    #[test]
    fn exit_stage_failures_never_report_success_and_retry_after_cleanup() {
        for fail_at in 0..4 {
            let mut progress = ExitProgress::default();
            let mut stage = 0;
            let result = exit_up_with(&mut progress, &["192.0.2.1".into()], |effect| {
                let adding = matches!(effect, ExitEffect::BypassAdd(_) | ExitEffect::GuardUp(_) | ExitEffect::DefaultAdd(_));
                if adding {
                    let failed = stage == fail_at;
                    stage += 1;
                    if failed { return Err(ApplyError::new(&["injected", "apply"], "permission denied")); }
                }
                match effect {
                    ExitEffect::BypassAdd(_) => Ok(true),
                    ExitEffect::GuardUp(pending) => { pending.push(vec!["guard".into()]); Ok(true) }
                    ExitEffect::GuardDown(pending) => { pending.clear(); Ok(false) }
                    _ => Ok(false),
                }
            });
            assert!(result.is_err(), "stage {fail_at} must not become UP");
            assert!(progress.bypass.is_empty());
            assert!(progress.defaults.is_empty());
            assert!(progress.v6_cleanup.is_empty());
            assert!(exit_up_with(&mut progress, &["192.0.2.1".into()], |effect| {
                match effect {
                    ExitEffect::BypassAdd(_) => Ok(true),
                    ExitEffect::GuardUp(pending) => { pending.push(vec!["guard".into()]); Ok(true) }
                    _ => Ok(false),
                }
            }).unwrap());
            assert_eq!(progress.defaults.len(), 2);
        }
    }

    #[test]
    fn guard_rollback_failure_retains_only_owned_half_and_retries_before_add() {
        let mut pending = Vec::new();
        let mut adds = 0;
        assert!(v6_block_tracked(RouteOs::Linux, "fp0", &mut pending, |command| {
            if command.iter().any(|s| s == "add") {
                adds += 1;
                if adds == 2 { return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "foreign second half")); }
            } else if !command.iter().any(|s| s == "unreachable") {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "rollback denied"));
            }
            Ok(())
        }).is_err());
        assert_eq!(pending, vec![v6_unblock_cmds(RouteOs::Linux, "fp0")[0].clone()]);
        let mut calls = Vec::new();
        assert!(v6_block_tracked(RouteOs::Linux, "fp0", &mut pending, |command| { calls.push(command.to_vec()); Ok(()) }).unwrap());
        assert_eq!(calls[0], v6_unblock_cmds(RouteOs::Linux, "fp0")[0]);
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn windows_guard_uses_ip_helper_operations_and_rolls_back_partial_add() {
        assert_eq!(v6_block_cmds(RouteOs::Windows, "fp0"), vec![
            argv(&["windows-route", "add", "::/1", "fp0"]),
            argv(&["windows-route", "add", "8000::/1", "fp0"]),
        ]);
        let mut calls = Vec::new(); let mut pending = Vec::new();
        assert!(v6_block_tracked(RouteOs::Windows, "fp0", &mut pending, |command| {
            calls.push(command.to_vec());
            if command == argv(&["windows-route", "add", "8000::/1", "fp0"]) {
                Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "route denied"))
            } else { Ok(()) }
        }).is_err());
        assert!(pending.is_empty());
        assert_eq!(calls.last().unwrap(), &argv(&["windows-route", "del", "::/1", "fp0"]));
        assert!(calls.iter().all(|command| command.first().unwrap() == "windows-route"));
    }

    #[test]
    fn v6_block_cmds_cover_both_halves_per_os() {
        // Linux: ordinary TUN routes, removed automatically with the interface.
        let cmds = v6_block_cmds(RouteOs::Linux, "fp0");
        assert_eq!(
            cmds,
            vec![
                argv(&["ip", "-6", "route", "add", "::/1", "dev", "fp0", "metric", "42760"]),
                argv(&["ip", "-6", "route", "add", "8000::/1", "dev", "fp0", "metric", "42760"]),
            ]
        );
        // macOS: into the tun interface, both halves.
        let cmds = v6_block_cmds(RouteOs::Macos, "utun7");
        assert_eq!(
            cmds,
            vec![
                argv(&["route", "-n", "add", "-inet6", "-net", "::/1", "-reject", "-interface", "utun7"]),
                argv(&["route", "-n", "add", "-inet6", "-net", "8000::/1", "-reject", "-interface", "utun7"]),
            ]
        );
        assert!(v6_block_cmds(RouteOs::Other, "fp0").is_empty());
    }

    #[test]
    fn v6_unblock_cmds_remove_exactly_what_block_installed() {
        let cmds = v6_unblock_cmds(RouteOs::Linux, "fp0");
        assert_eq!(
            cmds,
            vec![
                argv(&["ip", "-6", "route", "del", "::/1", "dev", "fp0", "metric", "42760"]),
                argv(&["ip", "-6", "route", "del", "8000::/1", "dev", "fp0", "metric", "42760"]),
            ]
        );
        let cmds = v6_unblock_cmds(RouteOs::Macos, "utun7");
        assert_eq!(
            cmds,
            vec![
                argv(&["route", "-n", "delete", "-inet6", "-net", "::/1", "-reject", "-interface", "utun7"]),
                argv(&["route", "-n", "delete", "-inet6", "-net", "8000::/1", "-reject", "-interface", "utun7"]),
            ]
        );
        assert!(v6_unblock_cmds(RouteOs::Other, "fp0").is_empty());
    }

    #[test]
    fn eexist_does_not_remove_foreign_routes_and_esrch_during_cleanup_is_tolerated() {
        let mut calls = Vec::new();
        let result = v6_block_with(RouteOs::Linux, "fp0", |cmd| {
            calls.push(cmd.to_vec());
            if cmd.iter().any(|s| s == "unreachable") { Err(std::io::Error::from_raw_os_error(libc::ESRCH)) }
            else { Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "File exists")) }
        });
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(calls.len(), 3); // two legacy deletes and first add; no ordinary delete
        assert!(calls.last().unwrap().iter().any(|v| v == "add"));
    }

    #[test]
    fn second_add_failure_rolls_back_first_and_teardown_reports_esrch() {
        let mut calls = Vec::new();
        let result = v6_block_with(RouteOs::Linux, "fp0", |cmd| {
            calls.push(cmd.to_vec());
            if cmd.iter().any(|s| s == "unreachable") { return Ok(()); }
            if cmd.iter().any(|s| s == "add") && cmd.iter().any(|s| s == "8000::/1") {
                Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "File exists"))
            } else { Ok(()) }
        });
        assert!(result.is_err());
        assert_eq!(calls.last(), v6_unblock_cmds(RouteOs::Linux, "fp0").first());
        let mut removed = 0;
        let failure = v6_unblock_with(&v6_unblock_cmds(RouteOs::Linux, "fp0"), |_| {
            removed += 1;
            Err(std::io::Error::from_raw_os_error(libc::ESRCH))
        });
        assert_eq!(removed, 2); // failure removing the first half must not skip the second
        assert_eq!(failure.unwrap_err().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn disabled_ipv6_degrades_but_other_failures_remain_retryable_errors() {
        assert!(!v6_guard_result(Err(std::io::ErrorKind::Unsupported.into())).unwrap());
        assert!(v6_guard_result(Err(std::io::ErrorKind::PermissionDenied.into())).is_err());
    }

    #[test]
    fn ipv6_carriers_use_the_ipv6_gateway_and_host_bypass_in_both_families() {
        let linux = parse_physical_v6_route(RouteOs::Linux, "default via fe80::1 dev eth0 proto ra metric 100\n").unwrap();
        assert_eq!(linux, ("fe80::1".into(), "eth0".into()));
        assert_eq!(bypass_cmd(RouteOs::Linux, "2001:db8::3", Some((&linux.0, &linux.1))).unwrap(),
            argv(&["ip", "-6", "route", "replace", "2001:db8::3/128", "via", "fe80::1", "dev", "eth0"]));
        let mac = parse_physical_v6_route(RouteOs::Macos, "   gateway: fe80::1%en0\n interface: en0\n").unwrap();
        assert_eq!(bypass_cmd(RouteOs::Macos, "2001:db8::3", Some((&mac.0, &mac.1))).unwrap(),
            argv(&["route", "-n", "add", "-inet6", "-net", "2001:db8::3/128", "fe80::1%en0"]));
        assert_eq!(bypass_cmd(RouteOs::Linux, "2001:db8::3", None).unwrap(),
            argv(&["ip", "-6", "route", "del", "2001:db8::3/128"]));
        assert_eq!(bypass_cmd(RouteOs::Linux, "192.0.2.3", Some(("192.0.2.1", "eth0"))).unwrap(),
            argv(&["ip", "-4", "route", "replace", "192.0.2.3/32", "via", "192.0.2.1", "dev", "eth0"]));
        assert!(parse_physical_v6_route(RouteOs::Linux, "").is_none());
    }

    #[test]
    fn current_os_matches_build_target() {
        #[cfg(target_os = "linux")]
        assert_eq!(current_os(), RouteOs::Linux);
        #[cfg(target_os = "macos")]
        assert_eq!(current_os(), RouteOs::Macos);
    }
}
