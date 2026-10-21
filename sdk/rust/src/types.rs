// SPDX-License-Identifier: BSD-3-Clause
//! Typed DTOs mirroring the control-server's device-config wire shape
//! (`GET /api/v1/devices/:id/config`). Kept in sync with
//! `control-server/src/domain.rs`; all additive fields default so OLD control
//! servers (missing keys) still deserialize.

use serde::{Deserialize, Serialize};

/// A peer entry in a device's config (≈ wg `[Peer]`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub wg_public_key: String,
    /// Overlay addresses (`<v4>/32`, `<v6>/128`) + approved subnet routes; an
    /// approved default route (`0.0.0.0/0`) is still listed here for old nodes —
    /// new consumers strip it unless the user opted into an exit.
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// This peer is an approved exit (control-plane source of truth; AD-1/AD-2).
    /// Absent on old control servers ⇒ infer from a default prefix in
    /// `allowed_ips`.
    #[serde(default)]
    pub exit: Option<bool>,
}

impl PeerConfig {
    /// Preserve the difference between an explicit false and an old server's
    /// missing field, which is inferred from approved default prefixes.
    pub fn is_exit(&self) -> bool {
        self.exit.unwrap_or_else(|| self.allowed_ips.iter().any(|p| p.parse::<crate::prefix::IpPrefix>().is_ok_and(|p| p.length() == 0)))
    }
}

/// What a device fetches to configure itself + its peers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub network_id: String,
    pub config_epoch: u64,
    pub address_v4: Option<String>,
    pub address_v6: Option<String>,
    pub peers: Vec<PeerConfig>,
    #[serde(default)]
    pub relays: Vec<serde_json::Value>,
    #[serde(default)]
    pub mtu: Option<i32>,
    #[serde(default)]
    pub dns: Vec<String>,
    /// THIS device is an approved exit — the node enables forwarding/NAT while
    /// set (unless locally forced/vetoed). Absent on old control servers.
    #[serde(default)]
    pub self_exit: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn old_control_config_without_exit_fields_deserializes() {
        let v: DeviceConfig = serde_json::from_str(
            r#"{
                "network_id": "n1", "config_epoch": 7,
                "address_v4": "100.72.16.100", "address_v6": null,
                "peers": [{"wg_public_key": "k", "allowed_ips": ["100.72.16.1/32", "0.0.0.0/0"]}]
            }"#,
        )
        .expect("old shape must parse");
        assert!(!v.self_exit);
        assert_eq!(v.peers[0].exit, None);
        assert!(v.peers[0].is_exit());
    }

    #[test]
    fn explicit_exit_false_overrides_legacy_inference() {
        let peer: PeerConfig = serde_json::from_value(serde_json::json!({
            "wg_public_key": "key", "allowed_ips": ["0.0.0.0/0"], "exit": false,
        })).unwrap();
        assert!(!peer.is_exit());
    }

    #[test]
    fn new_control_config_carries_exit_flags() {
        let v: DeviceConfig = serde_json::from_str(
            r#"{
                "network_id": "n1", "config_epoch": 8,
                "address_v4": null, "address_v6": null, "peers": [],
                "self_exit": true
            }"#,
        )
        .expect("new shape must parse");
        assert!(v.self_exit);
    }
}
