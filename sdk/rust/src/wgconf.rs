//! WireGuard `wg.conf` parsing for batch import (`fp import`).
//!
//! A hub-side wg-quick config — one `[Interface]` plus N `[Peer]` sections —
//! fully enumerates a mesh's membership: the interface is this device, and every
//! `[Peer]` is a remote device (public key + its overlay `AllowedIPs` + reachable
//! `Endpoint`). Importing it registers all N+1 devices into a fluxpeer network,
//! preserving the fixed addresses. The grammar is tiny, so we hand-roll the parser
//! (no INI dep) and keep it zero-panic.
//!
//! The interface's `PrivateKey` never leaves this machine: we derive its public
//! key locally and send only that to the control-server.

use anyhow::{Result, anyhow, bail};
use base64::Engine;

/// The `[Interface]` section (this device).
#[derive(Debug, Default, Clone)]
pub struct WgInterface {
    /// base64 x25519 private key (stays local; we only ship the derived pubkey).
    pub private_key: Option<String>,
    /// Overlay addresses (`Address = 10.0.0.1/24, fd00::1/64`).
    pub address: Vec<String>,
    pub listen_port: Option<u16>,
    pub dns: Vec<String>,
    pub mtu: Option<i32>,
    /// A leading `# comment` naming the interface device, if present.
    pub name: Option<String>,
}

/// A `[Peer]` section (a remote device).
#[derive(Debug, Default, Clone)]
pub struct WgPeer {
    pub public_key: Option<String>,
    /// Overlay CIDRs this peer owns (`AllowedIPs = 10.0.0.5/32, fd00::5/128`).
    pub allowed_ips: Vec<String>,
    /// Reachable `ip:port` (the peer's own endpoint), if pinned.
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    /// A leading `# comment` naming this peer device, if present.
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WgConf {
    pub interface: WgInterface,
    pub peers: Vec<WgPeer>,
}

/// Split a comma-or-whitespace separated value into trimmed, non-empty items.
fn split_list(v: &str) -> Vec<String> {
    v.split([',', ' ', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Strip an inline `#`/`;` comment and surrounding whitespace.
fn strip_inline_comment(line: &str) -> &str {
    let end = line.find(['#', ';']).unwrap_or(line.len());
    line[..end].trim()
}

/// Parse a wg-quick config. Keys and section names are case-insensitive; values
/// are taken verbatim. Repeated `AllowedIPs`/`Address`/`DNS` lines accumulate.
pub fn parse(input: &str) -> Result<WgConf> {
    #[derive(PartialEq)]
    enum Sec {
        None,
        Iface,
        Peer,
    }
    let mut sec = Sec::None;
    let mut iface = WgInterface::default();
    let mut peers: Vec<WgPeer> = Vec::new();
    // The most recent comment line, consumed as the *name* of the next section.
    let mut pending_name: Option<String> = None;

    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#').or_else(|| line.strip_prefix(';')) {
            // A free-form comment names the section it sits in/precedes. Skip
            // structured `# key = value` notes. A comment right after a header
            // names the current section; otherwise it names the next one.
            let c = rest.trim();
            if !c.is_empty() && !c.contains('=') {
                match sec {
                    Sec::Iface if iface.name.is_none() => iface.name = Some(c.to_string()),
                    Sec::Peer if peers.last().is_some_and(|p| p.name.is_none()) => {
                        peers.last_mut().expect("peer present").name = Some(c.to_string());
                    }
                    _ => {}
                }
                pending_name = Some(c.to_string());
            }
            continue;
        }
        if let Some(hdr) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            match hdr.trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    sec = Sec::Iface;
                    iface.name = pending_name.take();
                }
                "peer" => {
                    sec = Sec::Peer;
                    peers.push(WgPeer {
                        name: pending_name.take(),
                        ..Default::default()
                    });
                }
                other => bail!("unknown section [{other}]"),
            }
            continue;
        }
        pending_name = None; // a non-comment line breaks the comment→section link

        let Some((key, val)) = line.split_once('=') else {
            bail!("malformed line (expected `key = value`): {line}");
        };
        let key = key.trim().to_ascii_lowercase();
        let val = strip_inline_comment(val);
        match sec {
            Sec::None => bail!("`{key}` appears before any [Interface]/[Peer] section"),
            Sec::Iface => match key.as_str() {
                "privatekey" => iface.private_key = Some(val.to_string()),
                "address" => iface.address.extend(split_list(val)),
                "listenport" => iface.listen_port = Some(val.parse().map_err(|_| anyhow!("bad ListenPort: {val}"))?),
                "dns" => iface.dns.extend(split_list(val)),
                "mtu" => iface.mtu = Some(val.parse().map_err(|_| anyhow!("bad MTU: {val}"))?),
                _ => {} // ignore Table/PreUp/PostUp/etc.
            },
            Sec::Peer => {
                let p = peers.last_mut().expect("peer pushed on section header");
                match key.as_str() {
                    "publickey" => p.public_key = Some(val.to_string()),
                    "allowedips" => p.allowed_ips.extend(split_list(val)),
                    "endpoint" => p.endpoint = Some(val.to_string()),
                    "persistentkeepalive" => {
                        p.persistent_keepalive = Some(val.parse().map_err(|_| anyhow!("bad PersistentKeepalive: {val}"))?)
                    }
                    _ => {} // ignore PresharedKey/etc.
                }
            }
        }
    }

    if sec == Sec::None {
        bail!("no [Interface] section found — is this a WireGuard config?");
    }
    Ok(WgConf { interface: iface, peers })
}

/// Derive the base64 x25519 public key from a base64 private key (wg key format).
pub fn public_key_from_private(private_b64: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(private_b64.trim())
        .map_err(|e| anyhow!("PrivateKey is not valid base64: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("PrivateKey must be 32 bytes, got {}", bytes.len()))?;
    let secret = fp_crypto::x25519::StaticSecret::from(arr);
    let public = fp_crypto::x25519::PublicKey::from(&secret);
    Ok(base64::engine::general_purpose::STANDARD.encode(public.to_bytes()))
}

/// The first IPv4 `/32`-style host address in a CIDR list (for `address_v4`),
/// returned without its prefix length (`10.0.0.5/32` → `10.0.0.5`).
pub fn first_v4(cidrs: &[String]) -> Option<String> {
    cidrs.iter().find_map(|c| {
        let host = c.split('/').next().unwrap_or(c);
        host.parse::<std::net::Ipv4Addr>().ok().map(|_| host.to_string())
    })
}

/// The first IPv6 host address in a CIDR list (for `address_v6`).
pub fn first_v6(cidrs: &[String]) -> Option<String> {
    cidrs.iter().find_map(|c| {
        let host = c.split('/').next().unwrap_or(c);
        host.parse::<std::net::Ipv6Addr>().ok().map(|_| host.to_string())
    })
}

#[cfg(test)]
mod test {
    use super::*;

    const SAMPLE: &str = "\
[Interface]
# home-hub
PrivateKey = QFX6Js8Abcd1234567890aBcDeFgHiJkLmNoPqRsTuV0=
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
DNS = 10.0.0.2
MTU = 1380

# laptop
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.0.0.5/32, fd00::5/128
Endpoint = 203.0.113.7:51820
PersistentKeepalive = 25

[Peer]
PublicKey = wH1B6lT5p2Hh3mGq9bXy0cZ4dE6fGhI8jKlMnOpQrS=  # phone
AllowedIPs = 10.0.0.6/32
";

    #[test]
    fn parses_interface_and_peers() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(c.interface.name.as_deref(), Some("home-hub"));
        assert_eq!(c.interface.address, vec!["10.0.0.1/24", "fd00::1/64"]);
        assert_eq!(c.interface.listen_port, Some(51820));
        assert_eq!(c.interface.dns, vec!["10.0.0.2"]);
        assert_eq!(c.interface.mtu, Some(1380));
        assert_eq!(c.peers.len(), 2);

        let p0 = &c.peers[0];
        assert_eq!(p0.name.as_deref(), Some("laptop"));
        assert_eq!(p0.public_key.as_deref(), Some("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="));
        assert_eq!(p0.allowed_ips, vec!["10.0.0.5/32", "fd00::5/128"]);
        assert_eq!(p0.endpoint.as_deref(), Some("203.0.113.7:51820"));
        assert_eq!(p0.persistent_keepalive, Some(25));

        // inline comment after the value is stripped (not folded into the key).
        assert_eq!(c.peers[1].public_key.as_deref(), Some("wH1B6lT5p2Hh3mGq9bXy0cZ4dE6fGhI8jKlMnOpQrS="));
        assert_eq!(c.peers[1].allowed_ips, vec!["10.0.0.6/32"]);
    }

    #[test]
    fn extracts_fixed_addresses() {
        let c = parse(SAMPLE).unwrap();
        assert_eq!(first_v4(&c.peers[0].allowed_ips).as_deref(), Some("10.0.0.5"));
        assert_eq!(first_v6(&c.peers[0].allowed_ips).as_deref(), Some("fd00::5"));
        assert_eq!(first_v4(&c.interface.address).as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn derives_public_key_from_private() {
        // Known x25519 vector: all-zero clamped scalar → fixed base point result.
        let priv_b64 = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let pub_b64 = public_key_from_private(&priv_b64).unwrap();
        // Deterministic: same private always yields the same public.
        assert_eq!(pub_b64, public_key_from_private(&priv_b64).unwrap());
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(&pub_b64).unwrap().len(), 32);
    }

    #[test]
    fn rejects_non_wireguard_input() {
        assert!(parse("just some text\nno sections here\n").is_err());
        assert!(parse("[Peer]\nPublicKey = abc=\n").is_ok()); // peer-only is allowed shape-wise
    }

    #[test]
    fn rejects_bad_private_key() {
        assert!(public_key_from_private("not-base64!!!").is_err());
        assert!(public_key_from_private(&base64::engine::general_purpose::STANDARD.encode([0u8; 16])).is_err());
    }

    #[test]
    fn case_insensitive_keys_and_sections() {
        let c = parse("[interface]\nprivatekey = abc=\nADDRESS = 10.0.0.1/24\n").unwrap();
        assert_eq!(c.interface.address, vec!["10.0.0.1/24"]);
    }
}
