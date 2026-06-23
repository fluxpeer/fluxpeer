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
