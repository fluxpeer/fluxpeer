// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use crate::apply::Runner;
use std::collections::{HashMap, HashSet};

struct Host {
    forwarding: bool, tokens: HashSet<String>, next_token: u64,
    anchors: HashMap<String, String>, commands: Vec<Vec<String>>, fail: Option<String>,
    main_nat: String, main_filter: String,
}
impl Host {
    fn new(forwarding: bool) -> Self {
        Self { forwarding, tokens: HashSet::from(["999".into()]), next_token: 1000, anchors: HashMap::from([("com.apple/other-app".into(), "foreign rules".into())]),
            commands: vec![], fail: None, main_nat: "nat-anchor \"com.apple/*\" all\n# custom NAT".into(),
            main_filter: "anchor \"com.apple/*\" all\nblock in on en0 all".into() }
    }
    fn enable_calls(&self) -> usize { self.commands.iter().filter(|args| args.as_slice() == ["pfctl", "-E"]).count() }
}
impl Runner for Host {
    fn run(&mut self, args: &[&str], input: Option<&str>) -> Result<String> {
        self.commands.push(args.iter().map(|s| s.to_string()).collect());
        if self.fail.as_deref() == Some(args.join(" ").as_str()) { return Err(apply::test_support::error(Some(1), "injected failure")); }
        match args {
            ["sysctl", "-n", "net.inet.ip.forwarding"] => return Ok(u8::from(self.forwarding).to_string()),
            ["sysctl", "-w", value] => self.forwarding = match *value { "net.inet.ip.forwarding=1" => true, "net.inet.ip.forwarding=0" => false, _ => panic!("unexpected sysctl: {value}") },
            ["pfctl", "-sn"] => return Ok(self.main_nat.clone()),
            ["pfctl", "-sr"] => return Ok(self.main_filter.clone()),
            ["pfctl", "-a", anchor, "-sn" | "-sr"] => return Ok(self.anchors.get(*anchor).cloned().unwrap_or_default()),
            ["pfctl", "-a", anchor, "-f", "-"] => { self.anchors.insert(anchor.to_string(), input.unwrap().into()); },
            ["pfctl", "-a", anchor, "-F", "nat" | "rules"] => { self.anchors.remove(*anchor); },
            ["pfctl", "-E"] => {
                self.next_token += 1; let token = self.next_token.to_string();
                assert!(self.tokens.insert(token.clone()));
                return Ok(format!("No ALTQ support in kernel\npf enabled\nToken : {token}\n"));
            },
            ["pfctl", "-X", token] => {
                assert_ne!(*token, "999", "foreign reference must survive");
                if !self.tokens.remove(*token) { return Err(apply::test_support::error(Some(1), "pf: token invalid\n")); }
            },
            _ => panic!("unexpected or unscoped host mutation: {args:?}"),
        }
        Ok(String::new())
    }
}
fn start(host: &mut Host, root: &Path, iface: &str, tun: &str) -> Result { up_with(host, root, iface, tun, "en0", "100.72.0.0/24") }

#[test]
fn two_members_release_only_owned_rules_tokens_and_last_forwarding_lease() {
    for initial in [false, true] {
        for order in [["fp0", "fp1"], ["fp1", "fp0"]] {
            let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(initial);
            let original = (host.main_nat.clone(), host.main_filter.clone());
            start(&mut host, dir.path(), "fp0", "utun3").unwrap();
            start(&mut host, dir.path(), "fp1", "utun4").unwrap();
            start(&mut host, dir.path(), "fp0", "utun3").unwrap();
            assert_eq!(host.enable_calls(), 2); assert!(host.forwarding);
            assert_eq!(host.tokens.len(), 3);
            let rules = &host.anchors["com.apple/250.fluxpeer.fp0"];
            assert!(rules.contains("nat on en0 inet from 100.72.0.0/24 to any tagged \"fluxpeer_667030\" -> (en0)"));
            assert!(rules.contains("pass in quick on utun3"));
            assert!(rules.contains("pass out quick on en0 inet tagged \"fluxpeer_667030\""));
            down_with(&mut host, dir.path(), order[0]).unwrap();
            assert!(host.forwarding); assert_eq!(host.tokens.len(), 2);
            assert!(host.anchors.contains_key(&anchor(order[1]).unwrap()));
            down_with(&mut host, dir.path(), order[0]).unwrap();
            down_with(&mut host, dir.path(), order[1]).unwrap();
            assert_eq!(host.forwarding, initial); assert_eq!(host.tokens, HashSet::from(["999".into()]));
            assert_eq!(host.anchors, HashMap::from([("com.apple/other-app".into(), "foreign rules".into())]));
            assert_eq!((host.main_nat, host.main_filter), original);
            assert!(!dir.path().join("baseline.json").exists());
        }
    }
}

#[test]
fn restart_recovers_membership_even_when_kernel_tun_changes_or_provider_is_disabled() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
    start(&mut host, dir.path(), "fp0", "utun3").unwrap();
    // No in-memory PF owner survives; startup and explicit down use the logical iface.
    down_with(&mut host, dir.path(), "fp0").unwrap();
    assert!(!host.forwarding); assert_eq!(host.tokens.len(), 1);
    start(&mut host, dir.path(), "fp0", "utun9").unwrap();
    assert!(!host.anchors["com.apple/250.fluxpeer.fp0"].contains("utun3"));
    down_with(&mut host, dir.path(), "fp0").unwrap();
    assert!(!path(dir.path(), "fp0", "pf.json").unwrap().exists());
}

#[test]
fn command_failures_retain_cleanup_obligations_and_retry_to_original_state() {
    for command in ["pfctl -a com.apple/250.fluxpeer.fp0 -f -", "pfctl -a com.apple/250.fluxpeer.fp0 -F nat",
        "pfctl -a com.apple/250.fluxpeer.fp0 -F rules", "pfctl -X 1001", "sysctl -w net.inet.ip.forwarding=0"] {
        let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
        if command.ends_with("-f -") {
            host.fail = Some(command.into());
            assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
        } else {
            start(&mut host, dir.path(), "fp0", "utun3").unwrap();
            host.fail = Some(command.into());
            assert!(down_with(&mut host, dir.path(), "fp0").is_err());
        }
        assert!(load(dir.path(), "fp0").unwrap().is_some());
        host.fail = None;
        down_with(&mut host, dir.path(), "fp0").unwrap();
        assert!(!host.forwarding); assert_eq!(host.tokens.len(), 1);
        assert!(load(dir.path(), "fp0").unwrap().is_none());
    }
}

#[test]
fn acquiring_receipt_recovers_crash_before_token_journal_and_released_token_is_retryable() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
    start(&mut host, dir.path(), "fp0", "utun3").unwrap();
    let mut owner = load(dir.path(), "fp0").unwrap().unwrap();
    owner.token = None; owner.acquiring = true;
    save(&State::lock(dir.path()).unwrap(), dir.path(), &owner).unwrap();
    down_with(&mut host, dir.path(), "fp0").unwrap();
    assert_eq!(host.tokens.len(), 1); assert_eq!(host.enable_calls(), 1);
    start(&mut host, dir.path(), "fp0", "utun8").unwrap();
    let token = load(dir.path(), "fp0").unwrap().unwrap().token.unwrap();
    host.tokens.remove(&token); // Crash after kernel released it, before journal update.
    down_with(&mut host, dir.path(), "fp0").unwrap();
    assert_eq!(host.tokens.len(), 1); assert!(!host.forwarding);
}

#[test]
fn uncertain_acquire_never_guesses_foreign_token_or_enables_twice() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
    start(&mut host, dir.path(), "fp0", "utun3").unwrap();
    let mut owner = load(dir.path(), "fp0").unwrap().unwrap();
    owner.token = None; owner.acquiring = true;
    save(&State::lock(dir.path()).unwrap(), dir.path(), &owner).unwrap();
    fs::write(path(dir.path(), "fp0", "enable.log").unwrap(), "Token : ").unwrap();
    assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
    assert!(down_with(&mut host, dir.path(), "fp0").is_err());
    assert_eq!(host.enable_calls(), 1); assert_eq!(host.tokens.len(), 2);
    assert!(!host.forwarding); // Restore forwarding even if token ownership is uncertain.
    assert!(load(dir.path(), "fp0").unwrap().unwrap().acquiring);
    fs::write(path(dir.path(), "fp0", "enable.log").unwrap(), "Token : 1001\n").unwrap();
    down_with(&mut host, dir.path(), "fp0").unwrap();
    assert_eq!(host.tokens.len(), 1);
}

#[test]
fn crash_before_enable_spawn_and_reboot_do_not_release_unowned_tokens() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
    let old_boot = boot_root(dir.path(), "11111111-1111-1111-1111-111111111111").unwrap();
    let new_boot = boot_root(dir.path(), "22222222-2222-2222-2222-222222222222").unwrap();
    let state = State::lock(&old_boot).unwrap();
    let owner = Owner { iface: "fp0".into(), token: None, acquiring: true, retiring: false };
    save(&state, &old_boot, &owner).unwrap(); drop(state);
    down_with(&mut host, &old_boot, "fp0").unwrap();
    assert_eq!(host.enable_calls(), 0); assert_eq!(host.tokens.len(), 1);
    start(&mut host, &old_boot, "fp0", "utun3").unwrap();
    host.forwarding = false; host.tokens.remove("1001"); host.anchors.remove("com.apple/250.fluxpeer.fp0");
    let before = host.commands.len();
    down_with(&mut host, &new_boot, "fp0").unwrap();
    assert_eq!(host.commands.len(), before);
    assert!(boot_root(dir.path(), "../../other").is_err());
}

#[test]
fn preflight_rejects_injection_missing_hooks_and_foreign_anchor_without_mutation() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
    for (iface, tun, phys, cidr) in [("../bad", "utun3", "en0", "100.72.0.0/24"), ("fp0", "utun3\npass all", "en0", "100.72.0.0/24"),
        ("fp0", "utun3", "en0;echo", "100.72.0.0/24"), ("fp0", "utun3", "en0", "100.72.0.0/24\npass all"), ("fp0", "utun3", "en0", "::/0")] {
        assert!(up_with(&mut host, dir.path(), iface, tun, phys, cidr).is_err());
    }
    assert!(host.commands.is_empty());
    host.main_nat.clear();
    assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
    host.main_nat = "nat-anchor \"com.apple/*\" all".into();
    host.main_filter = "anchor \"com.apple/*\" on en1".into();
    assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
    host.main_filter = "anchor \"com.apple/*\" all".into();
    host.anchors.insert(anchor("fp0").unwrap(), "foreign".into());
    assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
    assert_eq!(host.enable_calls(), 0); assert!(!host.forwarding);
    assert!(load(dir.path(), "fp0").unwrap().is_none());
    for invalid in ["", "Token : 123", "Token : -1\n", "Token : 1\nToken : 2", "Token : 18446744073709551616", "Token : 12;echo"] { assert!(token(invalid).is_err()); }
}

#[test]
fn system_receipt_captures_stderr_and_preserves_failed_command_evidence() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("receipt");
    let output = apply::System.run_recorded(&["sh", "-c", "echo stdout; echo 'Token : 123' >&2"], &path).unwrap();
    assert_eq!(token(&output).unwrap(), "123");
    assert_eq!(crate::carriers::read_private(&path).unwrap().unwrap(), output.as_bytes());
    assert!(apply::System.run_recorded(&["sh", "-c", "exit 0"], &path).is_err());
    let failed = dir.path().join("failed");
    let error = apply::System.run_recorded(&["sh", "-c", "echo DIOCSTARTREF >&2; exit 1"], &failed).unwrap_err();
    assert_eq!(error.exit_code, Some(1)); assert!(error.stderr.contains("DIOCSTARTREF"));
    assert!(fs::read_to_string(failed).unwrap().contains("DIOCSTARTREF"));
}

#[test]
fn failed_forwarding_acquisition_remains_recoverable_without_a_pf_reference() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
    host.fail = Some("sysctl -w net.inet.ip.forwarding=1".into());
    assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
    assert!(path(dir.path(), "fp0", "lease").unwrap().exists());
    assert_eq!(host.enable_calls(), 0);
    host.fail = None;
    down_with(&mut host, dir.path(), "fp0").unwrap();
    assert!(!host.forwarding); assert_eq!(host.tokens.len(), 1);
    assert!(!dir.path().join("baseline.json").exists());
}

#[test]
fn corrupt_ownership_never_flushes_or_releases_foreign_resources() {
    let dir = tempfile::tempdir().unwrap(); let mut host = Host::new(false);
    start(&mut host, dir.path(), "fp0", "utun3").unwrap();
    let journal = path(dir.path(), "fp0", "pf.json").unwrap();
    let original = fs::read(&journal).unwrap();
    let before = host.commands.len();
    fs::write(&journal, b"broken").unwrap();
    assert!(down_with(&mut host, dir.path(), "fp0").is_err());
    assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
    assert_eq!(host.commands.len(), before);
    fs::remove_file(&journal).unwrap();
    assert!(down_with(&mut host, dir.path(), "fp0").is_err());
    assert!(start(&mut host, dir.path(), "fp0", "utun3").is_err());
    assert_eq!(host.tokens.len(), 2);
    State::lock(dir.path()).unwrap().save(&journal, &original).unwrap();
    down_with(&mut host, dir.path(), "fp0").unwrap();
}

#[test]
fn concurrent_members_serialize_ownership_and_keep_foreign_state() {
    #[derive(Clone)]
    struct Shared(std::sync::Arc<parking_lot::Mutex<Host>>);
    impl Runner for Shared {
        fn run(&mut self, args: &[&str], input: Option<&str>) -> Result<String> { self.0.lock().run(args, input) }
    }
    let dir = tempfile::tempdir().unwrap();
    let shared = Shared(std::sync::Arc::new(parking_lot::Mutex::new(Host::new(false))));
    std::thread::scope(|scope| {
        let threads: Vec<_> = [("fp0", "utun3"), ("fp1", "utun4")].into_iter().map(|(iface, tun)| {
            let mut runner = shared.clone(); let root = dir.path();
            scope.spawn(move || up_with(&mut runner, root, iface, tun, "en0", "100.72.0.0/24"))
        }).collect();
        for thread in threads { thread.join().unwrap().unwrap(); }
    });
    assert_eq!(shared.0.lock().tokens.len(), 3);
    std::thread::scope(|scope| {
        let threads: Vec<_> = ["fp0", "fp1"].into_iter().map(|iface| {
            let mut runner = shared.clone(); let root = dir.path();
            scope.spawn(move || down_with(&mut runner, root, iface))
        }).collect();
        for thread in threads { thread.join().unwrap().unwrap(); }
    });
    let host = shared.0.lock();
    assert!(!host.forwarding); assert_eq!(host.tokens, HashSet::from(["999".into()]));
    assert_eq!(host.anchors.len(), 1);
}

#[test]
fn token_is_retained_when_io_fails_after_acquisition_and_spawn_failure_can_retry() {
    struct LateFailure(Host);
    impl Runner for LateFailure {
        fn run(&mut self, args: &[&str], input: Option<&str>) -> Result<String> { self.0.run(args, input) }
        fn run_recorded(&mut self, args: &[&str], receipt: &Path) -> Result<String> {
            self.0.run_recorded(args, receipt)?;
            Err(ApplyError::io(args, std::io::Error::new(std::io::ErrorKind::PermissionDenied, "injected fsync failure after acquire")))
        }
    }
    let dir = tempfile::tempdir().unwrap(); let mut runner = LateFailure(Host::new(false));
    assert!(up_with(&mut runner, dir.path(), "fp0", "utun3", "en0", "100.72.0.0/24").is_err());
    assert_eq!(load(dir.path(), "fp0").unwrap().unwrap().token.as_deref(), Some("1001"));
    down_with(&mut runner, dir.path(), "fp0").unwrap();
    assert_eq!(runner.0.tokens, HashSet::from(["999".into()]));
    let receipt = dir.path().join("spawn-receipt");
    let error = apply::System.run_recorded(&["/nonexistent-fluxpeer-command-for-test"], &receipt).unwrap_err();
    assert_eq!(error.kind, std::io::ErrorKind::NotFound);
    assert!(!receipt.exists());
}
