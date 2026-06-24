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
    if cidr == "0.0.0.0/0" || cidr == "::/0" {
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
    if cidr == "0.0.0.0/0" || cidr == "::/0" {
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
    let d = cidr(dst);
    #[cfg(target_os = "macos")]
    {
        let _ = phys; // macOS `route` resolves the gateway's interface itself
        let _ = Command::new("route").args(["-n", "delete", "-net", &d]).status();
        let _ = Command::new("route").args(["-n", "add", "-net", &d, gateway]).status();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = Command::new("ip")
        .args(["route", "replace", &d, "via", gateway, "dev", phys])
        .status();
}

pub(crate) fn bypass_del(dst: &str) {
    let d = cidr(dst);
    #[cfg(target_os = "macos")]
    let _ = Command::new("route").args(["-n", "delete", "-net", &d]).status();
    #[cfg(not(target_os = "macos"))]
    let _ = Command::new("ip").args(["route", "del", &d]).status();
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
        match Command::new("ip").args(["route", "get", ip]).output() {
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
pub(crate) fn exit_up(dev: &str, gateway: &str, phys: &str, bypass: &[String], dns: Option<&str>) {
    // Bypass FIRST (carrier must be reachable before we hijack the default), then
    // the split-default over the tun.
    for b in bypass {
        bypass_add(b, gateway, phys);
    }
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
        "exit-node (full-tunnel) UP"
    );
}

/// Tear down full-tunnel: remove the split-default + bypass routes + reset DNS.
/// MUST run on shutdown, or the box is left with a broken default route + DNS.
pub(crate) fn exit_down(dev: &str, bypass: &[String]) {
    route_del("0.0.0.0/1", dev);
    route_del("128.0.0.0/1", dev);
    for b in bypass {
        bypass_del(b);
    }
    reset_dns(dev);
    tracing::info!(dev, "exit-node (full-tunnel) DOWN");
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
