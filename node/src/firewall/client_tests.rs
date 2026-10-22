// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use crate::apply::{Runner, test_support::{Scripted, error}};
use std::collections::HashMap;

#[derive(Default)]
struct Host {
    tables: HashMap<String, String>,
    chains: HashMap<String, String>,
    hooks: HashMap<String, Vec<String>>,
    commands: Vec<Vec<String>>,
    scripts: Vec<String>,
    deny: bool,
}
impl Runner for Host {
    fn run(&mut self, args: &[&str], input: Option<&str>) -> Result<String> {
        self.commands.push(args.iter().map(|s| s.to_string()).collect());
        if self.deny { return Err(error(Some(1), "Permission denied")); }
        let mut normalized = args.to_vec();
        if matches!(normalized.as_slice(), ["iptables" | "ip6tables", "-w", "10", ..]) { normalized.drain(1..3); }
        match normalized.as_slice() {
            ["nft", "-f", "-"] => {
                let script = input.unwrap(); self.scripts.push(script.into());
                let table = script.lines().next().unwrap().strip_prefix("add table inet ").unwrap();
                self.tables.insert(table.into(), script.into());
            },
            ["nft", "-j", "list", "table", "inet", table] => {
                let script = self.tables.get(*table).ok_or_else(|| error(Some(1), "No such file or directory"))?;
                let mut items = vec![serde_json::json!({"chain":{"name":"output","hook":"output","policy":"drop"}})];
                for line in script.lines() {
                    if let Some((_, rest)) = line.split_once("comment \"") {
                        let comment = rest.split('"').next().unwrap();
                        items.push(serde_json::json!({"rule":{"comment":comment}}));
                    }
                }
                return Ok(serde_json::json!({"nftables":items}).to_string());
            },
            ["nft", "delete", "table", "inet", table] => { self.tables.remove(*table); },
            [restore @ ("iptables-restore" | "ip6tables-restore"), "--wait", "10", "--noflush"] => {
                let bin = restore.strip_suffix("-restore").unwrap();
                let script = input.unwrap(); self.scripts.push(script.into());
                let chain = script.lines().nth(1).unwrap().split_whitespace().next().unwrap().trim_start_matches(':');
                self.chains.insert(format!("{bin}/{chain}"), script.lines().filter(|line| line.starts_with("-A ")).collect::<Vec<_>>().join("\n"));
            },
            [bin, "-S", "OUTPUT"] => return Ok(self.hooks.get(*bin).cloned().unwrap_or_default().join("\n")),
            [bin, "-I", "OUTPUT", "1", "-j", chain] => { self.hooks.entry(bin.to_string()).or_default().insert(0, format!("-A OUTPUT -j {chain}")); },
            [bin, "-S", chain] => return self.chains.get(&format!("{bin}/{chain}")).cloned().ok_or_else(|| error(Some(1), "No chain/target/match by that name.")),
            [bin, "-C", "OUTPUT", "-j", chain] => {
                if !self.hooks.get(*bin).is_some_and(|hooks| hooks.contains(&format!("-A OUTPUT -j {chain}"))) { return Err(error(Some(1), "Bad rule")); }
            },
            [bin, "-D", "OUTPUT", "-j", chain] => {
                let hooks = self.hooks.get_mut(*bin).unwrap();
                let at = hooks.iter().position(|hook| hook == &format!("-A OUTPUT -j {chain}")).unwrap();
                hooks.remove(at);
            },
            [bin, "-F", chain] => { self.chains.insert(format!("{bin}/{chain}"), String::new()); },
            [bin, "-X", chain] => { self.chains.remove(&format!("{bin}/{chain}")); },
            other => panic!("unexpected command: {other:?}"),
        }
        Ok(String::new())
    }
}
fn ips() -> Vec<String> { vec!["192.0.2.1".into(), "2001:db8::1".into()] }

#[test]
fn opt_in_default_split_and_unsupported_are_explicit() {
    for mode in [None, Some("off"), Some("")] { assert!(!requested(true, mode)); }
    assert!(!requested(false, Some("auto")));
    assert!(requested(true, Some("auto")));
    assert!(requested(true, Some(&"ab".repeat(32))));
    assert!(!validate_config(&serde_json::json!({})).unwrap());
    for value in [serde_json::json!("true"), serde_json::json!(1), serde_json::Value::Null] {
        assert!(validate_config(&serde_json::json!({"kill_switch":value})).is_err());
    }
    if cfg!(target_os = "linux") { supported(true).unwrap(); }
    else { assert_eq!(supported(true).unwrap_err().kind(), std::io::ErrorKind::Unsupported); }
    if cfg!(target_os = "macos") {
        assert_eq!(supported(true).unwrap_err().to_string(), "macOS client kill-switch is not supported in this release");
    }
    supported(false).unwrap();
}

#[test]
fn output_policy_has_only_own_tun_carriers_and_link_exceptions() {
    let plan = Plan::new("fp0", "nft", &ips()).unwrap();
    let mut host = Host::default(); install(&mut host, &plan).unwrap();
    let script = &host.tables[&plan.table().unwrap()];
    for rule in ["hook output priority -150; policy drop", "oifname \"lo\" accept", "oifname \"fp0\" accept", "ip daddr 192.0.2.1 accept", "ip6 daddr 2001:db8::1 accept", "udp sport 68 udp dport 67", "udp sport 546 udp dport 547", "ip daddr 169.254.0.0/16", "ip6 daddr fe80::/10"] { assert!(script.contains(rule), "{rule}"); }
    for forbidden in ["ct state", "0.0.0.0/0", "::/0", "fp*", "dport 53", "forward", "flush ruleset"] { assert!(!script.contains(forbidden), "{forbidden}"); }
    assert!(Plan::new("fp0", "nft", &["0.0.0.0/0".into()]).is_err());
    assert!(Plan::new("bad;iface", "nft", &[]).is_err());
    assert!(Plan::new("fp0", "unknown", &[]).is_err());
}

#[test]
fn nft_nat_replacement_and_engine_drop_preserve_output_until_explicit_clear() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
    sync_with(&mut host, dir.path(), "fp0", &ips(), false, Some("nft")).unwrap();
    let output = Plan::new("fp0", "nft", &ips()).unwrap().table().unwrap();
    let policy = host.tables[&output].clone();
    super::super::nft_with(&mut host, super::super::Operation::Up, "eth0", "fp0", &super::super::instance("fp0").unwrap(), "100.72.0.0/24").unwrap();
    super::super::nft_with(&mut host, super::super::Operation::Down, "eth0", "fp0", &super::super::instance("fp0").unwrap(), "").unwrap();
    assert_eq!(host.tables[&output], policy);
    // A new process reloads durable policy; revoked/unreachable exits do not
    // participate in guard activation and never request clear().
    let restored = load(dir.path(), "fp0").unwrap().unwrap();
    assert!(healthy(&mut host, &restored).unwrap());
    let before = host.scripts.len(); repair_with(&mut host, dir.path(), "fp0").unwrap();
    assert_eq!(host.scripts.len(), before);
    clear_with(&mut host, dir.path(), "fp0").unwrap();
    assert!(!host.tables.contains_key(&output)); assert!(load(dir.path(), "fp0").unwrap().is_none());
}

#[test]
fn reload_and_partial_flush_are_repaired_from_durable_policy() {
    for backend in ["nft", "iptables"] {
        let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
        sync_with(&mut host, dir.path(), "fp0", &ips(), false, Some(backend)).unwrap();
        let plan = load(dir.path(), "fp0").unwrap().unwrap();
        host.tables.clear(); host.chains.clear(); host.hooks.clear();
        repair_with(&mut host, dir.path(), "fp0").unwrap();
        assert!(healthy(&mut host, &plan).unwrap());
        if backend == "nft" { host.tables.get_mut(&plan.table().unwrap()).unwrap().retain(|c| c != ':'); }
        else { host.chains.insert("ip6tables/FPO_fp0".into(), String::new()); }
        assert!(!healthy(&mut host, &plan).unwrap());
        repair_with(&mut host, dir.path(), "fp0").unwrap(); assert!(healthy(&mut host, &plan).unwrap());
        host.deny = true;
        assert!(repair_with(&mut host, dir.path(), "fp0").is_err());
        assert!(clear_with(&mut host, dir.path(), "fp0").is_err());
        assert!(load(dir.path(), "fp0").unwrap().is_some());
    }
}

#[test]
fn iptables_hooks_precede_external_jumps_and_repair_displacement() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
    for bin in ["iptables", "ip6tables"] { host.hooks.insert(bin.into(), vec!["-A OUTPUT -j DOCKER-USER".into()]); }
    sync_with(&mut host, dir.path(), "fp0", &ips(), false, Some("iptables")).unwrap();
    let plan = load(dir.path(), "fp0").unwrap().unwrap();
    for bin in ["iptables", "ip6tables"] {
        assert_eq!(host.hooks[bin][0], "-A OUTPUT -j FPO_fp0");
        assert!(host.chains[&format!("{bin}/FPO_fp0")].ends_with("-j DROP"));
        host.hooks.get_mut(bin).unwrap().insert(0, "-A OUTPUT -j EXTERNAL".into());
    }
    repair_with(&mut host, dir.path(), "fp0").unwrap(); assert!(healthy(&mut host, &plan).unwrap());
    clear_with(&mut host, dir.path(), "fp0").unwrap();
    assert!(host.chains.is_empty());
    for bin in ["iptables", "ip6tables"] { assert_eq!(host.hooks[bin], ["-A OUTPUT -j EXTERNAL", "-A OUTPUT -j DOCKER-USER"]); }
}

#[test]
fn endpoint_transition_retains_old_only_until_commit_and_other_instances_survive_down() {
    for backend in ["nft", "iptables"] {
        let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
        for tun in ["fp0", "custom1"] { sync_with(&mut host, dir.path(), tun, &ips(), false, Some(backend)).unwrap(); }
        let next = vec!["192.0.2.2".into()];
        let union = sync_with(&mut host, dir.path(), "fp0", &next, true, None).unwrap();
        assert_eq!(union.len(), 3);
        assert_eq!(sync_with(&mut host, dir.path(), "fp0", &next, false, None).unwrap(), next);
        clear_with(&mut host, dir.path(), "fp0").unwrap();
        let other = load(dir.path(), "custom1").unwrap().unwrap();
        // Multiple iptables guards may displace one another at the head, but
        // removing one never removes the other guard or its persisted policy.
        if backend == "iptables" { assert!(host.chains.contains_key("iptables/FPO_custom1")); }
        else { assert!(healthy(&mut host, &other).unwrap()); }
    }
}

#[test]
fn install_failure_keeps_repair_obligation_and_does_not_swallow_ipv6_failure() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = Host { deny: true, ..Host::default() };
    assert!(sync_with(&mut host, dir.path(), "fp0", &ips(), false, Some("nft")).is_err());
    assert!(load(dir.path(), "fp0").unwrap().is_some());
    host.deny = false; repair_with(&mut host, dir.path(), "fp0").unwrap();
    let mut runner = Scripted::new(vec![Ok(String::new()), Ok(String::new()), Ok(String::new()), Err(error(None, "missing ip6tables-restore"))]);
    assert!(install(&mut runner, &Plan::new("fp0", "iptables", &ips()).unwrap()).is_err());
    assert_eq!(runner.commands.last().unwrap()[0], "ip6tables-restore");
}

#[test]
fn periodic_validation_never_runs_more_often_than_thirty_seconds() {
    let now = Instant::now();
    assert!(due(None, now));
    assert!(!due(Some(now), now + Duration::from_secs(29)));
    assert!(due(Some(now), now + Duration::from_secs(30)));
}

#[test]
fn guard_failure_is_visible_and_throttled_while_new_carriers_apply_immediately() {
    let now = Instant::now(); let mut guard = Guard::default();
    let mut calls = 0;
    let failure = error(Some(1), "Permission denied");
    for seconds in [0, 2, 29, 30] {
        let result = guard.sync_using(&ips(), false, now + Duration::from_secs(seconds), |_, _| { calls += 1; Err(failure.clone()) });
        assert_eq!(result, Err(failure.clone()));
    }
    assert_eq!(calls, 2);
    let next = vec!["192.0.2.2".into()];
    guard.sync_using(&next, false, now + Duration::from_secs(31), |ips, _| { calls += 1; Ok(ips.to_vec()) }).unwrap();
    guard.sync_using(&next, true, now + Duration::from_secs(32), |_, _| panic!("unchanged policy inspected too soon")).unwrap();
    assert_eq!(calls, 3);
}

#[tokio::test]
async fn explicit_down_removes_carriers_and_policy_only_for_its_instance() {
    for backend in ["nft", "iptables"] {
        let dir = tempfile::tempdir().unwrap(); let mut host = Host::default();
        for tun in ["fp0", "fp1"] {
            let cache = crate::carriers::Cache::open(dir.path(), tun, false).unwrap();
            cache.resolve_with("control.test", |_| std::future::ready(Ok(vec!["192.0.2.1".parse().unwrap()]))).await.unwrap();
            sync_with(&mut host, dir.path(), tun, &cache.addresses(), false, Some(backend)).unwrap(); cache.arm();
        }
        clear_with(&mut host, dir.path(), "fp0").unwrap();
        assert!(!crate::carriers::cache_path(dir.path(), "fp0").unwrap().exists());
        assert!(load(dir.path(), "fp0").unwrap().is_none());
        assert!(crate::carriers::cache_path(dir.path(), "fp1").unwrap().exists());
        assert!(healthy(&mut host, &load(dir.path(), "fp1").unwrap().unwrap()).unwrap());
        assert!(host.scripts.iter().all(|script| !script.contains("dport 53")));
    }
}

#[tokio::test]
async fn recovered_exit_refreshes_cache_and_adds_new_policy_before_pruning_old_ips() {
    for backend in ["nft", "iptables"] {
        let root = tempfile::tempdir().unwrap(); let mut host = Host::default();
        let cache = crate::carriers::Cache::open(root.path(), "fp0", false).unwrap();
        cache.resolve_with("relay.test", |_| std::future::ready(Ok(vec!["192.0.2.1".parse().unwrap()]))).await.unwrap();
        sync_with(&mut host, root.path(), "fp0", &cache.addresses(), false, Some(backend)).unwrap(); cache.arm();
        cache.exit_ready(true);
        cache.resolve_with("relay.test", |_| std::future::ready(Ok(vec!["192.0.2.2".parse().unwrap()]))).await.unwrap();
        let added = sync_with(&mut host, root.path(), "fp0", &cache.addresses(), true, None).unwrap();
        assert_eq!(added, ["192.0.2.1", "192.0.2.2"]);
        let pruned = sync_with(&mut host, root.path(), "fp0", &cache.addresses(), false, None).unwrap();
        assert_eq!(pruned, ["192.0.2.2"]);
        assert!(healthy(&mut host, &load(root.path(), "fp0").unwrap().unwrap()).unwrap());
        assert_eq!(crate::carriers::Cache::open(root.path(), "fp0", true).unwrap().addresses(), pruned);
        assert!(host.scripts.iter().all(|script| !script.contains("dport 53")));
    }
}
