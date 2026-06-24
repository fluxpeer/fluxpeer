//! fluxpeer Rust SDK: typed async client for the control-server
//! `/api/v1` surface. Used by the `fp` CLI and embeddable in third-party tools.

use anyhow::{Context, Result};
use serde_json::{Value, json};

pub mod wgconf;

/// Default control-server base URL.
pub const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// Build the device-import list from a parsed wg.conf: the `[Interface]` as one device
/// (unless `skip_interface`), then each `[Peer]`. Returns `(devices, warnings)` suitable
/// for [`Client::import_devices`]. The interface's private key is never sent — only its
/// derived public key.
pub fn build_import_devices(conf: &wgconf::WgConf, default_name: &str, skip_interface: bool) -> Result<(Vec<Value>, Vec<String>)> {
    let mut devices = Vec::new();
    let mut warnings = Vec::new();

    if !skip_interface {
        let priv_b64 = conf
            .interface
            .private_key
            .as_deref()
            .context("[Interface] has no PrivateKey — cannot derive its public key (use --skip-interface)")?;
        let pubkey = wgconf::public_key_from_private(priv_b64)?;
        let name = conf
            .interface
            .name
            .clone()
            .unwrap_or_else(|| default_name.to_string());
        devices.push(json!({
            "name": name,
            "wg_public_key": pubkey,
            "address_v4": wgconf::first_v4(&conf.interface.address),
            "address_v6": wgconf::first_v6(&conf.interface.address),
            "endpoints": [],
        }));
    }

    for (i, peer) in conf.peers.iter().enumerate() {
        let Some(pubkey) = peer.public_key.as_deref().filter(|k| !k.is_empty()) else {
            warnings.push(format!("peer #{} has no PublicKey — skipped", i + 1));
            continue;
        };
        let name = peer
            .name
            .clone()
            .unwrap_or_else(|| format!("imported-{}", short_key(pubkey)));
        if peer.allowed_ips.is_empty() {
            warnings.push(format!("peer \"{name}\" has no AllowedIPs — imported with no fixed address"));
        }
        devices.push(json!({
            "name": name,
            "wg_public_key": pubkey,
            "address_v4": wgconf::first_v4(&peer.allowed_ips),
            "address_v6": wgconf::first_v6(&peer.allowed_ips),
            "endpoints": peer.endpoint.clone().map(|e| vec![e]).unwrap_or_default(),
        }));
    }
    Ok((devices, warnings))
}

/// A short, filename-safe tag from a base64 public key (for auto-naming peers).
fn short_key(pubkey: &str) -> String {
    pubkey.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)] // non-test items intentionally follow
mod import_test {
    use super::*;

    #[test]
    fn build_import_devices_maps_interface_and_peers() {
        let conf = wgconf::parse(
            "[Interface]\n# hub\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.1/24\n\n# laptop\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.5/32\nEndpoint = 203.0.113.7:51820\n",
        )
        .unwrap();

        // With the interface included: 1 derived hub device + 1 peer.
        let (devs, warns) = build_import_devices(&conf, "wg0.conf", false).unwrap();
        assert_eq!(devs.len(), 2);
        assert!(warns.is_empty());
        assert_eq!(devs[0]["name"], "hub");
        assert_eq!(devs[0]["address_v4"], "10.0.0.1");
        assert!(devs[0]["wg_public_key"].as_str().unwrap().len() >= 40); // derived b64 pubkey
        assert_eq!(devs[1]["name"], "laptop");
        assert_eq!(devs[1]["address_v4"], "10.0.0.5");
        assert_eq!(devs[1]["endpoints"][0], "203.0.113.7:51820");

        // --skip-interface drops the hub (peers only) and needs no PrivateKey.
        let (peers_only, _) = build_import_devices(&conf, "wg0.conf", true).unwrap();
        assert_eq!(peers_only.len(), 1);
        assert_eq!(peers_only[0]["name"], "laptop");
    }
}

/// HTTP client for the control-server API.
pub struct Client {
    base: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base: impl Into<String>) -> Self {
        // Authenticate management calls with the admin password as a bearer when
        // `FLUXPEER_ADMIN_PASSWORD` is set (the control-server accepts the password
        // directly or a session token). Device-scoped calls pass their enroll-issued
        // auth token here; truly open endpoints ignore it.
        let pw = std::env::var("FLUXPEER_ADMIN_PASSWORD").unwrap_or_default();
        Self::with_password(base, &pw)
    }

    /// Like [`Client::new`] but with an explicit admin bearer (e.g. typed into a
    /// GUI), instead of reading `FLUXPEER_ADMIN_PASSWORD` from the environment. An
    /// empty `password` sends no auth header (fine only for truly open endpoints).
    pub fn with_password(base: impl Into<String>, password: &str) -> Self {
        let mut builder = reqwest::Client::builder();
        if !password.is_empty()
            && let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {password}"))
        {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::AUTHORIZATION, val);
            builder = builder.default_headers(headers);
        }
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            http: builder.build().unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base, path)
    }

    pub async fn create_network(&self, name: &str) -> Result<Value> {
        self.http
            .post(self.url("/networks"))
            .json(&json!({ "name": name }))
            .send()
            .await
            .context("request failed")?
            .error_for_status()?
            .json()
            .await
            .context("decode response")
    }

    pub async fn list_networks(&self) -> Result<Value> {
        self.http
            .get(self.url("/networks"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn create_invite(
        &self,
        network_id: &str,
        max_uses: Option<u32>,
        expires_at: Option<i64>,
    ) -> Result<Value> {
        self.http
            .post(self.url(&format!("/networks/{network_id}/invites")))
            .json(&json!({ "max_uses": max_uses, "expires_at": expires_at }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Batch-register devices parsed from a WireGuard `wg.conf` (admin-gated). Each
    /// entry carries a fixed `address_v4`/`address_v6` (preserved verbatim from the
    /// config's `AllowedIPs`) and optional pinned `endpoints`. Idempotent on public
    /// key: already-enrolled keys are reported as skipped. Returns
    /// `{ "created": [...], "skipped": [...] }`.
    pub async fn import_devices(&self, network_id: &str, devices: &Value) -> Result<Value> {
        self.http
            .post(self.url(&format!("/networks/{network_id}/devices/import")))
            .json(&json!({ "devices": devices }))
            .send()
            .await
            .context("request failed")?
            .error_for_status()
            .context("import rejected")?
            .json()
            .await
            .context("decode import response")
    }

    pub async fn list_devices(&self, network_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/networks/{network_id}/devices")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Enroll a device with an invite code (open endpoint; no admin auth). Runs the
    /// two-round proof-of-possession (audit #11): proves we hold the wg PRIVATE key
    /// for the public key being enrolled, so a caller can't squat a key it doesn't
    /// own. Takes the wg private key (hex) — the public half and the ECDH proof are
    /// derived here and the private key never leaves the process. Returns the created
    /// device (id + overlay address + one-time `auth_token`). Used by `fluxpeer join`.
    pub async fn enroll(&self, invite_code: &str, name: &str, wg_private_key: &str) -> Result<Value> {
        use fp_crypto::x25519::{PublicKey, StaticSecret};

        let priv_bytes: [u8; 32] = hex::decode(wg_private_key)
            .ok()
            .and_then(|v| v.try_into().ok())
            .context("wg_private_key must be 32-byte hex")?;
        let sk = StaticSecret::from(priv_bytes);
        let pub_hex = hex::encode(PublicKey::from(&sk).to_bytes());

        // Round 1: fetch an ephemeral server key + challenge id for this public key.
        let chal: Value = self
            .http
            .post(self.url("/enroll/challenge"))
            .json(&json!({ "wg_public_key": pub_hex }))
            .send()
            .await
            .context("challenge request failed")?
            .error_for_status()
            .context("enroll challenge rejected")?
            .json()
            .await
            .context("decode challenge response")?;
        let challenge_id = chal["challenge_id"].as_str().context("challenge missing challenge_id")?;
        let server_pub: [u8; 32] = chal["server_pub"]
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| v.try_into().ok())
            .context("challenge server_pub not 32-byte hex")?;

        // Round 2: proof = DH(wg_priv, server_pub); the server recomputes DH(e_priv,
        // wg_pub) and compares — equal iff we hold wg_priv.
        let proof = hex::encode(sk.diffie_hellman(&PublicKey::from(server_pub)).to_bytes());

        self.http
            .post(self.url("/enroll"))
            .json(&json!({
                "invite_code": invite_code,
                "name": name,
                "wg_public_key": pub_hex,
                "challenge_id": challenge_id,
                "proof": proof,
            }))
            .send()
            .await
            .context("request failed")?
            .error_for_status()
            .context("enroll rejected (bad/expired invite or proof-of-possession failed?)")?
            .json()
            .await
            .context("decode enroll response")
    }

    /// Resolve a device's gateway connect params. Device-scoped control routes
    /// require the enroll-issued auth token as this client's bearer.
    /// Returns `{node_pubkey, node_addr, node_port, transport_protocol,
    /// iface_ipv4?, mtu?, dns, allowed_routes, config_epoch}` — what a thin/
    /// mobile node merges into its `ClientStartReq` to reach the mesh via a
    /// gateway peer. 404 → no peer in the network advertises an endpoint yet.
    pub async fn gateway(&self, device_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/devices/{device_id}/gateway")))
            .send()
            .await
            .context("request failed")?
            .error_for_status()
            .context("no gateway available for device")?
            .json()
            .await
            .context("decode gateway response")
    }

    /// Read a device's editable wg settings (mtu / dns / endpoint).
    pub async fn device_settings(&self, device_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/devices/{device_id}/settings")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Set a device's editable wg settings.
    pub async fn set_device_settings(&self, device_id: &str, settings: &Value) -> Result<()> {
        self.http
            .put(self.url(&format!("/devices/{device_id}/settings")))
            .json(settings)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Rename a device (admin-gated).
    pub async fn rename_device(&self, device_id: &str, name: &str) -> Result<Value> {
        self.http
            .patch(self.url(&format!("/devices/{device_id}")))
            .json(&json!({ "name": name }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        self.http
            .delete(self.url(&format!("/devices/{device_id}")))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn device_config(&self, device_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/devices/{device_id}/config")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Report a device's cumulative traffic stats (node → control). Device-scoped
    /// control routes require the enroll-issued auth token as this client's bearer.
    pub async fn report_stats(&self, device_id: &str, rx: i64, tx: i64, peers: &Value) -> Result<()> {
        self.http
            .post(self.url(&format!("/devices/{device_id}/stats")))
            .json(&json!({ "rx_bytes": rx, "tx_bytes": tx, "peers": peers }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// A device's latest traffic stats (admin).
    pub async fn device_stats(&self, device_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/devices/{device_id}/stats")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Per-device traffic rollup for a network (admin).
    pub async fn network_stats(&self, network_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/networks/{network_id}/stats")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Report a device's reachable candidate endpoints (disco). Device-scoped
    /// control routes require the enroll-issued auth token as this client's bearer.
    pub async fn set_endpoints(&self, device_id: &str, endpoints: &[String]) -> Result<()> {
        self.http
            .post(self.url(&format!("/devices/{device_id}/endpoints")))
            .json(&serde_json::json!({ "endpoints": endpoints }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn advertise_route(&self, device_id: &str, prefix: &str) -> Result<Value> {
        self.http
            .post(self.url(&format!("/devices/{device_id}/routes")))
            .json(&json!({ "prefix": prefix }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn approve_route(&self, route_id: &str) -> Result<()> {
        self.http
            .post(self.url(&format!("/routes/{route_id}/approve")))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn list_device_routes(&self, device_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/devices/{device_id}/routes")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn delete_route(&self, route_id: &str) -> Result<()> {
        self.http
            .delete(self.url(&format!("/routes/{route_id}")))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn register_relay(
        &self,
        region: &str,
        url: &str,
        network_id: Option<&str>,
        anytls: bool,
        stun_url: Option<&str>,
    ) -> Result<Value> {
        self.http
            .post(self.url("/relays"))
            .json(&json!({ "region": region, "url": url, "network_id": network_id, "anytls": anytls, "stun_url": stun_url }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn list_relays(&self, network_id: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/networks/{network_id}/relays")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn resolve(&self, network_id: &str, name: &str) -> Result<Value> {
        self.http
            .get(self.url(&format!("/networks/{network_id}/resolve/{name}")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }
}
