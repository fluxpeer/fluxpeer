//! Low-level helpers + wg/disco wire constants.

use std::net::{IpAddr, Ipv4Addr};

use fp_disco::Disco;

// WireGuard message types (first byte of the little-endian u32 type field).
pub(crate) const T_HANDSHAKE_INIT: u8 = 1;
pub(crate) const T_HANDSHAKE_RESP: u8 = 2;
pub(crate) const T_DATA: u8 = 4;

/// A handshaked peer whose direct path yields no authenticated packet for this
/// long is presumed dead; we re-handshake over the relay. We keepalive every 1s,
/// so this tolerates a few lost keepalives before falling back.
pub(crate) const LIVENESS_DEAD_SECS: u64 = 5;

/// WireGuard rekeys a session after this long (REKEY_AFTER_TIME). The initiator
/// re-handshakes over the current path: forward secrecy + nonce-exhaustion safety
/// (the crypto layer enforces no time-based expiry, only a hard nonce ceiling).
pub(crate) const REKEY_AFTER_SECS: u64 = 120;

/// Magic prefix distinguishing disco datagrams from wg packets on the shared UDP
/// socket (wg packets never start with this).
pub(crate) const DISCO_MAGIC: &[u8; 4] = b"fpd1";

pub(crate) fn disco_dgram(msg: &Disco) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(DISCO_MAGIC);
    out.extend_from_slice(&msg.encode());
    out
}

/// 16-byte MAC appended to an authenticated peer disco datagram.
pub(crate) const DISCO_MAC_LEN: usize = 16;
/// Reject an authenticated disco message whose embedded timestamp is older/newer
/// than this — bounds capture-and-replay (off-path forgery is already blocked by
/// the MAC). Loose enough to tolerate modest clock skew between peers.
pub(crate) const DISCO_REPLAY_WINDOW_SECS: u64 = 30;

/// Per-peer disco MAC key = static-static DH(own_priv, peer_pub). Symmetric (both
/// peers derive the same value) and computable as soon as both static public keys
/// are known — i.e. before any wg handshake — which is exactly when disco runs.
pub(crate) fn disco_shared(own_priv: &fp_crypto::x25519::StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32] {
    own_priv
        .diffie_hellman(&fp_crypto::x25519::PublicKey::from(*peer_pub))
        .to_bytes()
}

/// 12-byte disco tx_id = big-endian unix-seconds (8) ‖ random nonce (4). The MAC
/// binds it, so the receiver can enforce [`DISCO_REPLAY_WINDOW_SECS`].
pub(crate) fn disco_tx_id() -> [u8; 12] {
    let mut tx = [0u8; 12];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    tx[..8].copy_from_slice(&now.to_be_bytes());
    let _ = getrandom::getrandom(&mut tx[8..]);
    tx
}

/// Build an AUTHENTICATED peer disco datagram: `fpd1 ‖ encode(msg) ‖ MAC16`. The
/// MAC is keyed by the static-static DH secret, so an off-path attacker can't forge
/// a ping/pong that redirects a peer's path. The trailing tag is invisible to
/// `Disco::decode` (it reads its own length), so legacy parsers/routers ignore it.
pub(crate) fn auth_disco_dgram(disco_key: &[u8; 32], msg: &Disco) -> Vec<u8> {
    let mut out = disco_dgram(msg);
    let tag = fp_crypto_noise::disco_mac(disco_key, &out);
    out.extend_from_slice(&tag);
    out
}

/// Verify the MAC on an authenticated disco datagram. `dgram` is the full datagram
/// (incl. `DISCO_MAGIC`); `body` is `dgram` past the magic; `used` is the encoded
/// frame length from `Disco::decode`. The MAC covers `DISCO_MAGIC ‖ frame` and
/// trails it in `body`. Constant-time compare; false if the tag is absent (a legacy
/// un-authenticated ping) or wrong.
pub(crate) fn disco_authed(disco_key: &[u8; 32], dgram: &[u8], body: &[u8], used: usize) -> bool {
    let Some(tag) = body.get(used..used + DISCO_MAC_LEN) else {
        return false;
    };
    let Some(macced) = dgram.get(..DISCO_MAGIC.len() + used) else {
        return false;
    };
    let expect = fp_crypto_noise::disco_mac(disco_key, macced);
    ct_eq(tag, &expect)
}

/// Reject a disco message whose embedded timestamp is outside the replay window.
pub(crate) fn disco_replay_ok(tx_id: &[u8; 12]) -> bool {
    let secs = u64::from_be_bytes([
        tx_id[0], tx_id[1], tx_id[2], tx_id[3], tx_id[4], tx_id[5], tx_id[6], tx_id[7],
    ]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.abs_diff(secs) <= DISCO_REPLAY_WINDOW_SECS
}

/// Constant-time byte-slice equality (don't leak MAC-match progress via timing).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("valid hex key").try_into().expect("32-byte key")
}

pub(crate) fn netmask_v4(prefix: u8) -> Ipv4Addr {
    let bits: u32 = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits)
}

/// Whether `ip` falls inside the IPv4 `cidr` (e.g. "100.72.16.5/32").
pub(crate) fn ip_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let (net, plen) = match cidr.split_once('/') {
        Some((n, p)) => (n, p.parse::<u8>().unwrap_or(32)),
        None => (cidr, 32),
    };
    let Ok(net) = net.parse::<Ipv4Addr>() else { return false };
    // plen 0 ⇒ match everything (0.0.0.0/0, the exit node). `u32::MAX << 32` is NOT 0
    // in Rust — the shift amount is masked to 5 bits — so /0 must be special-cased,
    // else a full-tunnel peer matches nothing and internet traffic is never routed.
    let mask = match plen {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

/// Primary local IPv4 on the route toward `host` (no packets sent).
pub(crate) fn local_ipv4_toward(host: &str) -> Option<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect(format!("{host}:9")).ok()?;
    match probe.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

pub(crate) fn url_host(url: &str) -> String {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', ':'])
        .next()
        .unwrap_or("")
        .to_string()
}

/// Little-endian u32 at offset `off` (wg session indices), if in bounds.
pub(crate) fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fp_crypto::x25519::{PublicKey, StaticSecret};

    fn keypair(seed: u8) -> (StaticSecret, [u8; 32]) {
        let s = StaticSecret::from([seed; 32]);
        let p = PublicKey::from(&s);
        (s, *p.as_bytes())
    }

    #[test]
    fn disco_key_is_symmetric() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);
        // DH(a_priv, b_pub) == DH(b_priv, a_pub): both ends derive the same key.
        assert_eq!(disco_shared(&a_priv, &b_pub), disco_shared(&b_priv, &a_pub));
    }

    #[test]
    fn authed_ping_roundtrips_and_verifies() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);
        let a_key = disco_shared(&a_priv, &b_pub); // A → B
        let msg = Disco::Ping {
            tx_id: disco_tx_id(),
            sender: a_pub,
        };
        let dgram = auth_disco_dgram(&a_key, &msg);
        let body = dgram.strip_prefix(DISCO_MAGIC).expect("magic");
        let (decoded, used) = Disco::decode(body).expect("decode");
        assert_eq!(decoded, msg);
        // B verifies with its own derivation of the same key.
        let b_key = disco_shared(&b_priv, &a_pub);
        assert!(disco_authed(&b_key, &dgram, body, used));
    }

    #[test]
    fn rejects_wrong_key_unauthed_and_tampered() {
        let (a_priv, a_pub) = keypair(1);
        let (_b_priv, b_pub) = keypair(2);
        let (c_priv, _c_pub) = keypair(3);
        let a_key = disco_shared(&a_priv, &b_pub);
        let msg = Disco::Ping {
            tx_id: disco_tx_id(),
            sender: a_pub,
        };
        let dgram = auth_disco_dgram(&a_key, &msg);
        let body = dgram.strip_prefix(DISCO_MAGIC).unwrap();
        let (_m, used) = Disco::decode(body).unwrap();

        // Wrong key (a third party that doesn't share the A↔B secret) fails.
        let wrong = disco_shared(&c_priv, &b_pub);
        assert!(!disco_authed(&wrong, &dgram, body, used));

        // A legacy/un-authenticated datagram (no trailing MAC) fails.
        let plain = disco_dgram(&msg);
        let pbody = plain.strip_prefix(DISCO_MAGIC).unwrap();
        let (_pm, pused) = Disco::decode(pbody).unwrap();
        assert!(!disco_authed(&a_key, &plain, pbody, pused));

        // A flipped MAC byte fails.
        let mut tampered = dgram.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let tbody = tampered.strip_prefix(DISCO_MAGIC).unwrap();
        assert!(!disco_authed(&a_key, &tampered, tbody, used));
    }

    #[test]
    fn replay_window_rejects_stale_timestamp() {
        // Fresh tx_id is within the window; an all-zero (epoch) timestamp is not.
        assert!(disco_replay_ok(&disco_tx_id()));
        assert!(!disco_replay_ok(&[0u8; 12]));
    }
}
