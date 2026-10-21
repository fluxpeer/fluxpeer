//! Cross-platform route + DNS management, including full-tunnel (exit-node) setup.
//! Modeled on the `fp-route` crate but run directly — the node is root, so it needs no
//! privileged-helper hop. `ip`/`resolvectl` on Linux, `route`/`scutil` on macOS.

use std::process::Command;

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
/// tunnel uses the split-default in [`exit_up`].
pub(crate) fn route_replace(cidr: &str, dev: &str) {
    if crate::control::is_default_prefix(cidr) {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("route").args(["-n", "delete", "-net", cidr]).status();
        let _ = Command::new("route")
            .args(["-n", "add", "-net", cidr, "-interface", dev])
            .status();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = Command::new("ip").args(["route", "replace", cidr, "dev", dev]).status();
}

/// Remove a route previously installed by [`route_replace`].
pub(crate) fn route_del(cidr: &str, dev: &str) {
    if crate::control::is_default_prefix(cidr) {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        let _ = dev; // macOS deletes by destination only
        let _ = Command::new("route").args(["-n", "delete", "-net", cidr]).status();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = Command::new("ip").args(["route", "del", cidr, "dev", dev]).status();
}

/// A bypass route: `dst` routes via the original physical `gateway` on `phys`
/// instead of the tunnel. The explicit device is REQUIRED — the split-default is
/// already installed, so a `via`-only route would resolve the gateway back through
/// the tun and loop. More specific than `0.0.0.0/1`, so it wins (split-exclude).
pub(crate) fn bypass_add(dst: &str, gateway: &str, phys: &str) {
    let v6 = dst.parse::<fluxpeer_sdk::prefix::IpPrefix>().is_ok_and(|p| p.network().is_ipv6());
    let v6_route = if v6 { physical_v6_route() } else { None };
    let (gateway, phys) = if v6 {
        let Some((gateway, phys)) = v6_route.as_ref() else {
            tracing::warn!(dst, "no IPv6 physical default; carrier bypass not needed until IPv6 is available");
            return;
        };
        (gateway.as_str(), phys.as_str())
    } else { (gateway, phys) };
    if current_os() == RouteOs::Macos {
        // Match the existing IPv4 replacement behavior, with the right family.
        bypass_del(dst);
    }
    if let Some(command) = bypass_cmd(current_os(), dst, Some((gateway, phys)))
        && let Err(error) = run_route_command(&command)
    {
        tracing::warn!(%error, dst, "carrier bypass installation failed");
    }
}

pub(crate) fn bypass_del(dst: &str) {
    if let Some(command) = bypass_cmd(current_os(), dst, None)
        && let Err(error) = run_route_command(&command)
    {
        tracing::warn!(%error, dst, "carrier bypass removal failed");
    }
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
fn physical_v6_route() -> Option<(String, String)> {
    let command = match current_os() {
        RouteOs::Linux => argv(&["ip", "-6", "route", "show", "default"]),
        RouteOs::Macos => argv(&["route", "-n", "get", "-inet6", "default"]),
        RouteOs::Other => return None,
    };
    let (program, args) = command.split_first()?;
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() { return None; }
    parse_physical_v6_route(current_os(), &String::from_utf8_lossy(&output.stdout))
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
pub(crate) fn default_gateway() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        s.lines()
            .find_map(|l| l.trim().strip_prefix("gateway:").map(|g| g.trim().to_string()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let parts: Vec<&str> = s.split_whitespace().collect();
        parts
            .iter()
            .position(|w| *w == "via")
            .and_then(|i| parts.get(i + 1))
            .map(|g| g.to_string())
    }
}

/// Does `dst` need an explicit bypass route? Only REMOTE destinations (routed via
/// the default gateway) get hijacked by the 0.0.0.0/1 split-default and must be
/// pinned; on-link / connected destinations (the LAN, an on-link carrier) already
/// win via their more-specific connected route, and adding a via-gateway route for
/// them would BREAK that on-link reachability.
pub(crate) fn needs_bypass(dst: &str) -> bool {
    let ip = dst.split('/').next().unwrap_or(dst);
    #[cfg(target_os = "macos")]
    {
        let _ = ip;
        true // macOS: pin conservatively (refine later)
    }
    #[cfg(not(target_os = "macos"))]
    {
        match Command::new("ip").args([if ip.contains(':') { "-6" } else { "-4" }, "route", "get", ip]).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains(" via "), // via a gateway ⇒ remote
            Err(_) => true,
        }
    }
}

/// The physical egress interface (the default route's device) — for exit-node NAT.
pub(crate) fn physical_iface() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("route").args(["-n", "get", "default"]).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        s.lines()
            .find_map(|l| l.trim().strip_prefix("interface:").map(|i| i.trim().to_string()))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let parts: Vec<&str> = s.split_whitespace().collect();
        parts
            .iter()
            .position(|w| *w == "dev")
            .and_then(|i| parts.get(i + 1))
            .map(|d| d.to_string())
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias",
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let t = s.trim();
        if t.is_empty() { None } else { Some(t.to_string()) }
    }
}

/// Bring up full-tunnel (exit node): the `0.0.0.0/1` + `128.0.0.0/1` split-default
/// over the tun (overrides the physical default WITHOUT deleting it — the wg-quick
/// trick), bypass routes for the carrier + excluded subnets via `gateway`, and DNS.
/// Returns whether IPv6 egress was blocked (see [`v6_block_up`]) so the teardown
/// removes exactly what we installed.
pub(crate) fn exit_up(dev: &str, gateway: &str, phys: &str, bypass: &[String], dns: Option<&str>) -> std::io::Result<bool> {
    // Install the leak guard even without a current v6 default: connectivity
    // may appear later while the full tunnel remains active. Fail before v4 UP.
    // Bypass FIRST (carrier must be reachable before we hijack the default), then
    // the split-default over the tun.
    for b in bypass {
        bypass_add(b, gateway, phys);
    }
    let v6_blocked = match v6_block_up(dev) {
        Ok(blocked) => blocked,
        Err(error) => {
            for destination in bypass { bypass_del(destination); }
            return Err(error);
        }
    };
    route_replace("0.0.0.0/1", dev);
    route_replace("128.0.0.0/1", dev);
    if let Some(d) = dns {
        set_dns(dev, d);
    }
    tracing::info!(
        dev,
        gateway,
        phys,
        bypass = bypass.len(),
        dns,
        v6_blocked,
        "exit-node (full-tunnel) UP"
    );
    Ok(v6_blocked)
}

/// Tear down full-tunnel: remove the split-default + bypass routes + reset DNS
/// (+ the IPv6 block iff WE installed it). MUST run on shutdown, or the box is
/// left with a broken default route + DNS.
pub(crate) fn exit_down(dev: &str, bypass: &[String], v6_blocked: bool) {
    route_del("0.0.0.0/1", dev);
    route_del("128.0.0.0/1", dev);
    for b in bypass {
        bypass_del(b);
    }
    if v6_blocked {
        v6_block_down(dev);
    }
    reset_dns(dev);
    tracing::info!(dev, "exit-node (full-tunnel) DOWN");
}

/// The route OS family, for command generation (unit-tested per variant).
/// Variants for other platforms look dead in a single-OS build — they exist
/// for the cross-platform tests.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum RouteOs {
    Linux,
    Macos,
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
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
    let Some((prog, args)) = c.split_first() else { return Err(std::io::Error::other("empty route command")); };
    let output = Command::new(prog).args(args).output()?;
    if output.status.success() { return Ok(()); }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let kind = if stderr.contains("No such process") || stderr.contains("not in table") {
        std::io::ErrorKind::NotFound
    } else if stderr.contains("File exists") { std::io::ErrorKind::AlreadyExists }
    else if stderr.contains("Address family not supported") || stderr.contains("IPv6 is disabled") {
        std::io::ErrorKind::Unsupported
    } else { std::io::ErrorKind::Other };
    Err(std::io::Error::new(kind, format!("{}: {}: {}", c.join(" "), output.status, stderr.trim())))
}

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
fn v6_block_with(os: RouteOs, dev: &str, mut run: impl FnMut(&[String]) -> std::io::Result<()>) -> std::io::Result<bool> {
    for command in v6_legacy_cleanup_cmds(os) {
        if let Err(error) = run(&command) {
            if error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) {
                tracing::debug!(%error, "no legacy IPv6 guard to remove");
            } else {
                tracing::warn!(%error, "legacy IPv6 guard cleanup failed");
                return Err(error);
            }
        }
    }
    let cmds = v6_block_cmds(os, dev);
    for (installed, command) in cmds.iter().enumerate() {
        if let Err(error) = run(command) {
            let undo: Vec<_> = v6_unblock_cmds(os, dev).into_iter().take(installed).collect();
            if let Err(rollback) = v6_unblock_with(&undo, &mut run) {
                tracing::error!(%rollback, "IPv6 block rollback failed");
            }
            return Err(error);
        }
    }
    Ok(!cmds.is_empty())
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

fn v6_block_up(dev: &str) -> std::io::Result<bool> {
    #[cfg(target_os = "linux")]
    if std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6").is_ok_and(|v| v.trim() == "1") {
        tracing::warn!("IPv6 is disabled; continuing IPv4 full-tunnel");
        return Ok(false);
    }
    let blocked = v6_guard_result(v6_block_with(current_os(), dev, run_route_command))?;
    if blocked { tracing::info!("IPv6 egress blocked in full-tunnel (not supported yet)"); }
    Ok(blocked)
}

fn v6_block_down(dev: &str) {
    if let Err(error) = v6_unblock_with(&v6_unblock_cmds(current_os(), dev), run_route_command) {
        tracing::error!(%error, "IPv6 guard removal incomplete");
    }
}

/// Exit SIDE: enable IPv4+IPv6 forwarding + NAT masquerade out `phys` so traffic from
/// peers routing 0.0.0.0/0 (or ::/0) through us reaches the internet. Linux only (the
/// common exit-node platform); idempotent on both stacks.
pub(crate) fn exit_gateway_up(phys: &str, tun: &str, overlay_cidr: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = overlay_cidr; // Linux masquerades by egress iface, not by source subnet.
        crate::firewall::detect().up(phys, tun);
    }
    #[cfg(target_os = "windows")]
    {
        let _ = phys; // WinNAT masquerades out the system's default route automatically.
        // Enable IPv4 forwarding so peer traffic transits the box; simplest is to set
        // it on every v4 interface (the tun must forward; the egress iface too).
        win_ps(&format!(
            "Set-NetIPInterface -InterfaceAlias '{tun}' -Forwarding Enabled -ErrorAction SilentlyContinue"
        ));
        win_ps(
            "Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled -ErrorAction SilentlyContinue",
        );
        // WinNAT (Windows 10+ built-in): masquerade the overlay subnet out the default
        // route. The winnat driver service defaults to manual/stopped — start it first.
        // Idempotent: drop any stale instance of our NAT before recreating it.
        win_ps("Start-Service winnat -ErrorAction SilentlyContinue");
        win_ps("Remove-NetNat -Name fluxpeer-exit -Confirm:$false -ErrorAction SilentlyContinue");
        win_ps(&format!(
            "New-NetNat -Name fluxpeer-exit -InternalIPInterfaceAddressPrefix '{overlay_cidr}' -ErrorAction SilentlyContinue"
        ));
        tracing::info!(tun, overlay_cidr, "exit-node GATEWAY up (WinNAT + forwarding)");
    }
    #[cfg(target_os = "macos")]
    {
        let _ = tun; // macOS NATs by source subnet, not by tun iface
        // 1. IPv4 forwarding.
        let _ = Command::new("sysctl").args(["-w", "net.inet.ip.forwarding=1"]).status();
        // 2. NAT via pf. Write our rule into a dedicated anchor file, then load a main
        // ruleset that PRESERVES the system (com.apple) anchors and adds ours, and
        // enable pf. Keeping the apple anchors avoids breaking AirDrop/stealth-mode.
        let anchor_path = "/etc/pf.anchors/fluxpeer-exit";
        let anchor_rule = format!("nat on {phys} from {overlay_cidr} to any -> ({phys})\n");
        if let Err(e) = std::fs::write(anchor_path, anchor_rule) {
            tracing::warn!(anchor_path, error = %e, "exit-node: cannot write pf anchor");
        } else {
            let main_ruleset = "\
scrub-anchor \"com.apple/*\"
nat-anchor \"com.apple/*\"
nat-anchor \"fluxpeer-exit\"
rdr-anchor \"com.apple/*\"
dummynet-anchor \"com.apple/*\"
anchor \"com.apple/*\"
load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"
load anchor \"fluxpeer-exit\" from \"/etc/pf.anchors/fluxpeer-exit\"
";
            // Remember if pf was off before us, so down() can leave no trace.
            let was_on = Command::new("pfctl")
                .args(["-s", "info"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: Enabled"))
                .unwrap_or(false);
            pfctl_load(main_ruleset);
            let _ = Command::new("pfctl").arg("-e").status(); // enable (harmless if already on)
            if !was_on {
                PF_ENABLED_BY_US.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            tracing::info!(phys, overlay_cidr, "exit-node GATEWAY up (pf nat + ip.forwarding)");
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = (phys, tun, overlay_cidr);
        tracing::warn!("exit-node gateway (forwarding+NAT) is unsupported on this platform");
    }
}

/// True if WE enabled pf (it was disabled before the exit gateway came up), so the
/// teardown can disable it again. Same-process up→down, so an atomic suffices.
#[cfg(target_os = "macos")]
static PF_ENABLED_BY_US: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Feed a complete pf ruleset to `pfctl -f -` on stdin (macOS exit-node NAT).
#[cfg(target_os = "macos")]
fn pfctl_load(ruleset: &str) {
    use std::io::Write;
    if let Ok(mut c) = Command::new("pfctl")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(si) = c.stdin.as_mut() {
            let _ = si.write_all(ruleset.as_bytes());
        }
        let _ = c.wait();
    }
}

/// Run a PowerShell one-liner with no console window (for the Windows exit-node
/// NAT/forwarding commands). Best-effort; errors are ignored like the unix path.
#[cfg(target_os = "windows")]
fn win_ps(script: &str) {
    use std::os::windows::process::CommandExt;
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .status();
}

pub(crate) fn exit_gateway_down(phys: &str, tun: &str) {
    #[cfg(target_os = "linux")]
    {
        crate::firewall::detect().down(phys, tun);
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (phys, tun);
        win_ps("Remove-NetNat -Name fluxpeer-exit -Confirm:$false -ErrorAction SilentlyContinue");
    }
    #[cfg(target_os = "macos")]
    {
        let _ = (phys, tun);
        // Flush our anchor + restore the system default ruleset (drops our nat-anchor),
        // then remove the anchor file. Leave ip.forwarding as-is (macOS is rarely an exit
        // node); pf itself is turned back off below only if we were the ones to enable it.
        let _ = Command::new("pfctl")
            .args(["-a", "fluxpeer-exit", "-F", "nat"])
            .status();
        let _ = Command::new("pfctl").args(["-f", "/etc/pf.conf"]).status();
        let _ = std::fs::remove_file("/etc/pf.anchors/fluxpeer-exit");
        // If pf was disabled before we turned it on, turn it back off (leave no trace).
        if PF_ENABLED_BY_US.swap(false, std::sync::atomic::Ordering::Relaxed) {
            let _ = Command::new("pfctl").arg("-d").status();
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    let _ = (phys, tun);
}

/// Point system DNS at `dns` (the exit node's gateway). Linux: resolvectl with a
/// catch-all routing domain (so ALL queries go through the tun), falling back to
/// /etc/resolv.conf. macOS: scutil dynamic store (best-effort).
fn set_dns(dev: &str, dns: &str) {
    #[cfg(target_os = "macos")]
    {
        let script =
            format!("d.init\nd.add ServerAddresses * {dns}\nset State:/Network/Service/fluxpeer-{dev}/DNS\nquit\n");
        use std::io::Write;
        if let Ok(mut c) = Command::new("scutil").stdin(std::process::Stdio::piped()).spawn() {
            if let Some(si) = c.stdin.as_mut() {
                let _ = si.write_all(script.as_bytes());
            }
            let _ = c.wait();
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        crate::dns::detect_for_iface(Some(dev)).set(dns);
    }
    #[cfg(windows)]
    {
        // Point the tun adapter's DNS at the exit gateway. The low interface metric
        // set during route setup makes Windows prefer this adapter's resolver.
        win_ps(&format!(
            "Set-DnsClientServerAddress -InterfaceAlias '{dev}' -ServerAddresses '{dns}' -ErrorAction SilentlyContinue"
        ));
        tracing::info!(dev, dns, "exit DNS via Set-DnsClientServerAddress");
    }
}

fn reset_dns(dev: &str) {
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        let script = format!("remove State:/Network/Service/fluxpeer-{dev}/DNS\nquit\n");
        if let Ok(mut c) = Command::new("scutil").stdin(std::process::Stdio::piped()).spawn() {
            if let Some(si) = c.stdin.as_mut() {
                let _ = si.write_all(script.as_bytes());
            }
            let _ = c.wait();
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    crate::dns::detect_for_iface(Some(dev)).clear();
    #[cfg(windows)]
    win_ps(&format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{dev}' -ResetServerAddresses -ErrorAction SilentlyContinue"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

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
