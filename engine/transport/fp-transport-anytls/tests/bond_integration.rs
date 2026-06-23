//! Integration test: verify bond multi-connection transport works end-to-end.
//!
//! Run: cargo test -p fp-transport-anytls --test bond_integration

use fp_transport_anytls::AnytlsConfig;
use std::time::Duration;

/// Test that AnytlsConfig defaults are sane
#[test]
fn test_config_defaults() {
    let cfg = AnytlsConfig::default();
    assert_eq!(cfg.bond_connections, 3);
    assert_eq!(cfg.effective_bond_connections(), 3);
    // Lowered from 30s/3 in the 2026-05-20 bond disconnect audit (middlebox
    // idle-reset observed at ~14s); see config.rs Default impl.
    assert_eq!(cfg.health_check_interval, Duration::from_secs(10));
    assert_eq!(cfg.max_consecutive_failures, 2);
}

/// Test bond_connections clamping
#[test]
fn test_config_clamp() {
    let cfg = AnytlsConfig {
        bond_connections: 0,
        ..AnytlsConfig::default()
    };
    assert_eq!(cfg.effective_bond_connections(), 1);
    let cfg = AnytlsConfig {
        bond_connections: 100,
        ..AnytlsConfig::default()
    };
    assert_eq!(cfg.effective_bond_connections(), 8);
    let cfg = AnytlsConfig {
        bond_connections: 5,
        ..AnytlsConfig::default()
    };
    assert_eq!(cfg.effective_bond_connections(), 5);
}

/// Password derived from same node_id must always produce the same result
/// (server and client both call derive_password with the same node_id)
#[test]
fn test_password_derivation_deterministic() {
    let node_id = "0E7B555F-BD7D-4B41-9183-4D3DF65D2179";
    let p1 = AnytlsConfig::derive_password(node_id);
    let p2 = AnytlsConfig::derive_password(node_id);
    assert_eq!(p1, p2);
    assert_eq!(p1.len(), 64); // SHA256 hex = 64 chars

    // Different node_id → different password
    let p3 = AnytlsConfig::derive_password("DIFFERENT-NODE-ID");
    assert_ne!(p1, p3);
}

/// with_node_id sets password automatically
#[test]
fn test_with_node_id() {
    let cfg = AnytlsConfig::with_node_id("test-node-123");
    assert!(!cfg.password.is_empty());
    assert_eq!(cfg.password, AnytlsConfig::derive_password("test-node-123"));
    // Other fields should be defaults
    assert_eq!(cfg.bond_connections, 3);
}
