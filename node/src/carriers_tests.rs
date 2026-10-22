// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use std::future::ready;
fn no_dns(_: String) -> std::future::Ready<io::Result<Vec<IpAddr>>> { panic!("unexpected system DNS") }
fn answer(ip: &str) -> Vec<IpAddr> { vec![ip.parse().unwrap()] }

#[tokio::test]
async fn first_use_resolves_all_carriers_before_arm_and_restart_never_calls_dns() {
    let dir = tempfile::tempdir().unwrap(); let cache = Cache::open(dir.path(), "fp0", false).unwrap();
    let mut events = Vec::new();
    for (host, ip) in [("control.test", "192.0.2.1"), ("relay.test", "192.0.2.2"), ("stun.test", "192.0.2.3")] {
        cache.resolve_with(host, |_| { events.push(host); ready(Ok(answer(ip))) }).await.unwrap();
    }
    events.push("arm"); cache.arm();
    assert_eq!(events, ["control.test", "relay.test", "stun.test", "arm"]);
    drop(cache);
    let retained = Cache::open(dir.path(), "fp0", true).unwrap();
    for (host, ip) in [("control.test", "192.0.2.1"), ("relay.test", "192.0.2.2"), ("stun.test", "192.0.2.3")] {
        assert_eq!(retained.resolve_with(host, no_dns).await.unwrap(), answer(ip));
    }
    let file: serde_json::Value = serde_json::from_slice(&read_private(&cache_path(dir.path(), "fp0").unwrap()).unwrap().unwrap()).unwrap();
    assert!(file["hosts"]["relay.test"]["updated_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn new_hostname_without_exit_blocks_until_exit_recovers_then_refreshes_ips() {
    let dir = tempfile::tempdir().unwrap(); let cache = Cache::open(dir.path(), "fp0", false).unwrap(); cache.arm();
    let error = cache.resolve_with("new.test", no_dns).await.unwrap_err();
    assert!(is_blocked(&error)); assert!(cache.diagnostic().unwrap().contains("kill_switch_dns_blocked: new.test"));
    cache.exit_ready(true);
    assert_eq!(cache.resolve_with("new.test", |_| ready(Ok(answer("192.0.2.5")))).await.unwrap(), answer("192.0.2.5"));
    cache.resolve_with("new.test", |_| ready(Ok(answer("192.0.2.6")))).await.unwrap();
    assert_eq!(cache.addresses(), ["192.0.2.6"]);
    assert!(cache.diagnostic().is_none());
    cache.exit_ready(false);
    assert_eq!(cache.resolve_with("new.test", |_| ready(Err(io::Error::other("must not run")))).await.unwrap(), answer("192.0.2.6"));
}

#[tokio::test]
async fn lost_exit_discards_inflight_dns_and_all_unreachable_cached_ips_are_visible() {
    let dir = tempfile::tempdir().unwrap(); let cache = Cache::open(dir.path(), "fp0", false).unwrap();
    let ips = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
    cache.resolve_with("relay.test", |_| ready(Ok(ips.clone()))).await.unwrap(); cache.arm(); cache.exit_ready(true);
    assert_eq!(cache.resolve_with("relay.test", |_| { cache.exit_ready(false); ready(Ok(answer("192.0.2.3"))) }).await.unwrap(), ips);
    cache.failed_addresses(answer("192.0.2.1")); assert!(cache.diagnostic().is_none());
    cache.failed_addresses(answer("192.0.2.2")); assert!(cache.diagnostic().unwrap().contains("relay.test"));
    cache.connected(answer("192.0.2.1")); assert!(cache.diagnostic().is_none());
    let error = cache.network_error("relay.test", io::Error::new(io::ErrorKind::TimedOut, "all control addresses timed out"));
    assert!(is_blocked(&error));
}

#[tokio::test]
async fn cache_is_per_iface_private_atomic_and_removed_on_explicit_cleanup() {
    let dir = tempfile::tempdir().unwrap(); let a = Cache::open(dir.path(), "fp0", false).unwrap();
    let b = Cache::open(dir.path(), "fp1", false).unwrap();
    a.resolve_with("control.test", |_| ready(Ok(answer("192.0.2.1")))).await.unwrap();
    b.resolve_with("control.test", |_| ready(Ok(answer("192.0.2.2")))).await.unwrap();
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(&a.path).unwrap().permissions().mode() & 0o777, 0o600); }
    let prior = std::fs::read(&a.path).unwrap();
    assert!(a.resolve_with("control.test", |_| ready(Err(io::Error::other("DNS failed")))).await.is_err());
    assert_eq!(std::fs::read(&a.path).unwrap(), prior);
    remove_at(dir.path(), "fp0").unwrap(); assert!(!a.path.exists());
    assert_eq!(Cache::open(dir.path(), "fp1", true).unwrap().cached("control.test").unwrap(), answer("192.0.2.2"));
    remove_at(dir.path(), "fp0").unwrap();
    assert!(cache_path(dir.path(), "../fp0").is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_and_lax_permissions_are_rejected_without_touching_targets() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap(); let target = dir.path().join("foreign"); std::fs::write(&target, "keep").unwrap();
    let path = cache_path(dir.path(), "fp0").unwrap(); symlink(&target, &path).unwrap();
    assert!(Cache::open(dir.path(), "fp0", true).is_err()); assert!(Cache::open(dir.path(), "fp0", false).is_err());
    assert!(remove_at(dir.path(), "fp0").is_err()); assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    std::fs::remove_file(&path).unwrap(); std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap(); assert!(Cache::open(dir.path(), "fp0", true).is_err());
}

#[test]
fn endpoints_keep_family_and_port_without_accepting_urls_or_credentials() {
    assert_eq!(endpoint_parts("relay.test:443").unwrap(), ("relay.test".into(), 443));
    assert_eq!(endpoint_parts("[2001:db8::1]:3478").unwrap(), ("2001:db8::1".into(), 3478));
    assert!(endpoint_parts("user:pass@relay.test:443").is_err());
    assert!(endpoint_parts("relay.test:443/path").is_err());
}
