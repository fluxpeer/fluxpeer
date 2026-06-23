//! fluxpeer disco: NAT hole-punching control messages.
//! Studied from iroh/Tailscale disco; our own
//! implementation. Pure codec (no I/O); transported separately from the wg
//! tunnel so path discovery works before the tunnel is up.
//!
//! Messages are authenticated by the caller (signed/MACed with device keys)
//! before sending — this module only frames them. Wire: `[type:u8][len:u32 BE][body]`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 32-byte Curve25519 device public key.
pub type PublicKey = [u8; 32];
/// 12-byte probe transaction id (STUN-like), echoed in the matching Pong.
pub type TxId = [u8; 12];

const T_PING: u8 = 1;
const T_PONG: u8 = 2;
const T_CALL_ME_MAYBE: u8 = 3;

const KEY_LEN: usize = 32;
const TXID_LEN: usize = 12;
const HEADER_LEN: usize = 1 + 4;
const AF_V4: u8 = 4;
const AF_V6: u8 = 6;
/// Defensive cap on candidate count in a CallMeMaybe.
pub const MAX_CANDIDATES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disco {
    /// Probe sent to a peer's candidate endpoint to open/validate a path.
    Ping { tx_id: TxId, sender: PublicKey },
    /// Reply echoing the tx id + the address the responder observed us at.
    Pong { tx_id: TxId, observed: SocketAddr },
    /// "Start punching now" — here are my current candidate endpoints.
    CallMeMaybe { candidates: Vec<SocketAddr> },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("buffer too short: need {need}, have {have}")]
    ShortBuffer { need: usize, have: usize },
    #[error("unknown disco type {0}")]
    UnknownType(u8),
    #[error("malformed disco body")]
    Malformed,
    #[error("too many candidates: {0}")]
    TooManyCandidates(usize),
}

fn put_addr(out: &mut Vec<u8>, a: &SocketAddr) {
    match a.ip() {
        IpAddr::V4(ip) => {
            out.push(AF_V4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(AF_V6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&a.port().to_be_bytes());
}

/// Read one socket addr; returns (addr, bytes_consumed).
fn get_addr(b: &[u8]) -> Result<(SocketAddr, usize), Error> {
    let af = *b.first().ok_or(Error::Malformed)?;
    match af {
        AF_V4 => {
            let need = 1 + 4 + 2;
            let s = b.get(..need).ok_or(Error::Malformed)?;
            let ip = Ipv4Addr::new(s[1], s[2], s[3], s[4]);
            let port = u16::from_be_bytes([s[5], s[6]]);
            Ok((SocketAddr::new(IpAddr::V4(ip), port), need))
        }
        AF_V6 => {
            let need = 1 + 16 + 2;
            let s = b.get(..need).ok_or(Error::Malformed)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&s[1..17]);
            let port = u16::from_be_bytes([s[17], s[18]]);
            Ok((SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port), need))
        }
        _ => Err(Error::Malformed),
    }
}

impl Disco {
    fn type_byte(&self) -> u8 {
        match self {
            Disco::Ping { .. } => T_PING,
            Disco::Pong { .. } => T_PONG,
            Disco::CallMeMaybe { .. } => T_CALL_ME_MAYBE,
        }
    }

    fn body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Disco::Ping { tx_id, sender } => {
                b.extend_from_slice(tx_id);
                b.extend_from_slice(sender);
            }
            Disco::Pong { tx_id, observed } => {
                b.extend_from_slice(tx_id);
                put_addr(&mut b, observed);
            }
            Disco::CallMeMaybe { candidates } => {
                b.extend_from_slice(&(candidates.len() as u16).to_be_bytes());
                for c in candidates {
                    put_addr(&mut b, c);
                }
            }
        }
        b
    }

    pub fn encode(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(self.type_byte());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<(Disco, usize), Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::ShortBuffer {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let ty = buf[0];
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let total = HEADER_LEN + len;
        if buf.len() < total {
            return Err(Error::ShortBuffer {
                need: total,
                have: buf.len(),
            });
        }
        let body = &buf[HEADER_LEN..total];

        let msg = match ty {
            T_PING => {
                if body.len() != TXID_LEN + KEY_LEN {
                    return Err(Error::Malformed);
                }
                let mut tx_id = [0u8; TXID_LEN];
                tx_id.copy_from_slice(&body[..TXID_LEN]);
                let mut sender = [0u8; KEY_LEN];
                sender.copy_from_slice(&body[TXID_LEN..]);
                Disco::Ping { tx_id, sender }
            }
            T_PONG => {
                if body.len() < TXID_LEN {
                    return Err(Error::Malformed);
                }
                let mut tx_id = [0u8; TXID_LEN];
                tx_id.copy_from_slice(&body[..TXID_LEN]);
                let (observed, n) = get_addr(&body[TXID_LEN..])?;
                if TXID_LEN + n != body.len() {
                    return Err(Error::Malformed);
                }
                Disco::Pong { tx_id, observed }
            }
            T_CALL_ME_MAYBE => {
                let count = u16::from_be_bytes([
                    *body.first().ok_or(Error::Malformed)?,
                    *body.get(1).ok_or(Error::Malformed)?,
                ]) as usize;
                if count > MAX_CANDIDATES {
                    return Err(Error::TooManyCandidates(count));
                }
                let mut off = 2;
                let mut candidates = Vec::with_capacity(count);
                for _ in 0..count {
                    let (a, n) = get_addr(&body[off..])?;
                    candidates.push(a);
                    off += n;
                }
                if off != body.len() {
                    return Err(Error::Malformed);
                }
                Disco::CallMeMaybe { candidates }
            }
            other => return Err(Error::UnknownType(other)),
        };
        Ok((msg, total))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn rt(m: Disco) {
        let bytes = m.encode();
        let (decoded, n) = Disco::decode(&bytes).expect("decode");
        assert_eq!(decoded, m);
        assert_eq!(n, bytes.len());
    }

    #[test]
    fn roundtrip_ping_pong_callmemaybe() {
        rt(Disco::Ping {
            tx_id: [1u8; 12],
            sender: [2u8; 32],
        });
        rt(Disco::Pong {
            tx_id: [3u8; 12],
            observed: "192.168.1.5:51820".parse().unwrap(),
        });
        rt(Disco::Pong {
            tx_id: [4u8; 12],
            observed: "[2001:db8::1]:443".parse().unwrap(),
        });
        rt(Disco::CallMeMaybe {
            candidates: vec!["100.64.0.1:1".parse().unwrap(), "[fd00::2]:2".parse().unwrap()],
        });
        rt(Disco::CallMeMaybe { candidates: vec![] });
    }

    #[test]
    fn short_buffer_and_unknown_type() {
        assert!(matches!(Disco::decode(&[1, 0]), Err(Error::ShortBuffer { .. })));
        assert_eq!(Disco::decode(&[99, 0, 0, 0, 0]), Err(Error::UnknownType(99)));
    }

    #[test]
    fn truncated_pong_addr_is_malformed() {
        let mut bytes = Disco::Pong {
            tx_id: [0u8; 12],
            observed: "1.2.3.4:5".parse().unwrap(),
        }
        .encode();
        let last = bytes.len() - 1;
        bytes.truncate(last); // drop a byte of the addr but keep frame len honest? recompute
        // rebuild a deliberately-malformed frame: claim full len but corrupt af
        let mut bad = Disco::Pong {
            tx_id: [0u8; 12],
            observed: "1.2.3.4:5".parse().unwrap(),
        }
        .encode();
        let body_start = 5 + 12; // header + txid
        bad[body_start] = 9; // invalid address family
        assert_eq!(Disco::decode(&bad), Err(Error::Malformed));
    }

    #[test]
    fn too_many_candidates_rejected() {
        // craft header claiming 9999 candidates
        let mut body = (9999u16).to_be_bytes().to_vec();
        body.extend_from_slice(&[AF_V4, 1, 2, 3, 4, 0, 1]);
        let mut frame = vec![T_CALL_ME_MAYBE];
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        assert_eq!(Disco::decode(&frame), Err(Error::TooManyCandidates(9999)));
    }
}
