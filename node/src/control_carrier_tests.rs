// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use reqwest::dns::Resolve;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn protected_control_client_uses_pinned_dns_and_preserves_host_and_bearer() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1]; socket.read_exact(&mut byte).await.unwrap(); request.push(byte[0]);
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
        String::from_utf8(request).unwrap().to_lowercase()
    });
    let mut cfg: Config = serde_json::from_value(serde_json::json!({"private_key":"00".repeat(32), "device_id":"device",
        "control_server":format!("http://control.invalid:{port}"), "listen_port":0, "tun_name":"fp0", "prefix_len":24, "auth_token":"test-device-token"})).unwrap();
    cfg.carrier_dns = Some(Arc::new(CarrierDns { host:"control.invalid".into(), addresses:parking_lot::RwLock::new(vec!["127.0.0.1".parse().unwrap()]) }));
    tokio::time::timeout(Duration::from_secs(2), mk_client(&cfg).device_config("device")).await.unwrap().unwrap();
    let request = server.await.unwrap();
    assert!(request.contains(&format!("host: control.invalid:{port}")));
    assert!(request.contains("authorization: bearer test-device-token"));
}

#[tokio::test]
async fn protected_resolver_rejects_other_hosts_and_uses_refreshed_pins() {
    let dns = CarrierDns { host:"control.invalid".into(), addresses:parking_lot::RwLock::new(vec!["192.0.2.1".parse().unwrap()]) };
    assert!(dns.resolve("relay.invalid".parse().unwrap()).await.is_err());
    assert_eq!(dns.resolve("control.invalid".parse().unwrap()).await.unwrap().next().unwrap().ip().to_string(), "192.0.2.1");
    *dns.addresses.write() = vec!["192.0.2.2".parse().unwrap()];
    assert_eq!(dns.resolve("control.invalid".parse().unwrap()).await.unwrap().next().unwrap().ip().to_string(), "192.0.2.2");
}

#[tokio::test]
async fn unreachable_cached_control_reports_dns_blocked_without_resolving_again() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port(); drop(listener);
    let root = tempfile::tempdir().unwrap();
    let cache = crate::carriers::Cache::open(root.path(), "fp0", false).unwrap();
    let ips = cache.resolve_with("control.invalid", |_| std::future::ready(Ok(vec!["127.0.0.1".parse().unwrap()]))).await.unwrap(); cache.arm();
    let mut cfg: Config = serde_json::from_value(serde_json::json!({"private_key":"00".repeat(32), "device_id":"device",
        "control_server":format!("http://control.invalid:{port}"), "listen_port":0, "tun_name":"fp0", "prefix_len":24})).unwrap();
    cfg.carrier_dns = Some(Arc::new(CarrierDns { host:"control.invalid".into(), addresses:parking_lot::RwLock::new(ips) }));
    cfg.carrier_cache = Some(cache.clone());
    let error = fetch_relays(&cfg).await.unwrap_err();
    assert!(error.to_string().contains("kill_switch_dns_blocked: control.invalid"));
    assert!(!terminal_control_error(&error));
    assert!(cache.diagnostic().unwrap().contains("connect an exit or disable kill-switch"));
}
