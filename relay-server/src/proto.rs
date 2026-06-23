//! fluxpeer relay wire protocol (DERP-style).
//!
//! Frames are addressed by device Curve25519 public key; payloads are opaque
//! (wg-encrypted) so the relay never decrypts. Wire format of one
//! frame: `[type:u8][len:u32 BE][body:len]`, which is also self-describing for
//! stream framing over any fluxpeer transport (anytls/443 etc.).
//!
//! This module is pure (no I/O) and fully unit-tested; the networking server is
//! built on top.

/// 32-byte Curve25519 public key used to address relay peers.
pub type PublicKey = [u8; 32];

/// Max opaque payload per relayed datagram (mirrors iroh-relay's 64 KiB).
pub const MAX_PACKET_SIZE: usize = 64 * 1024;

const T_CLIENT_INFO: u8 = 1;
const T_SERVER_INFO: u8 = 2;
const T_SEND_PACKET: u8 = 3;
const T_RECV_PACKET: u8 = 4;
const T_PING: u8 = 5;
const T_PONG: u8 = 6;
const T_PEER_GONE: u8 = 7;
const T_HEALTH: u8 = 8;
const T_RESTARTING: u8 = 9;

const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 1 + 4; // type + u32 length

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// client→relay handshake: who I am + my relay protocol version.
    ClientInfo {
        pubkey: PublicKey,
        protocol_version: u32,
    },
    /// relay→client handshake ack: relay's protocol version.
    ServerInfo {
        protocol_version: u32,
    },
    /// client→relay: forward `payload` to `dst`.
    SendPacket {
        dst: PublicKey,
        payload: Vec<u8>,
    },
    /// relay→client: a `payload` arrived from `src`.
    RecvPacket {
        src: PublicKey,
        payload: Vec<u8>,
    },
    Ping {
        data: [u8; 8],
    },
    Pong {
        data: [u8; 8],
    },
    /// relay→client: the addressed peer is no longer connected.
    PeerGone {
        pubkey: PublicKey,
    },
    Health,
    Restarting,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("buffer too short: need {need}, have {have}")]
    ShortBuffer { need: usize, have: usize },
    #[error("unknown frame type {0}")]
    UnknownType(u8),
    #[error("bad body length {0} for frame type")]
    BadLength(usize),
    #[error("payload too large: {0} > {MAX_PACKET_SIZE}")]
    TooLarge(usize),
}

impl Frame {
    fn type_byte(&self) -> u8 {
        match self {
            Frame::ClientInfo { .. } => T_CLIENT_INFO,
            Frame::ServerInfo { .. } => T_SERVER_INFO,
            Frame::SendPacket { .. } => T_SEND_PACKET,
            Frame::RecvPacket { .. } => T_RECV_PACKET,
            Frame::Ping { .. } => T_PING,
            Frame::Pong { .. } => T_PONG,
            Frame::PeerGone { .. } => T_PEER_GONE,
            Frame::Health => T_HEALTH,
            Frame::Restarting => T_RESTARTING,
        }
    }

    fn body(&self) -> Vec<u8> {
        match self {
            Frame::ClientInfo {
                pubkey,
                protocol_version,
            } => {
                let mut b = Vec::with_capacity(KEY_LEN + 4);
                b.extend_from_slice(pubkey);
                b.extend_from_slice(&protocol_version.to_be_bytes());
                b
            }
            Frame::ServerInfo { protocol_version } => protocol_version.to_be_bytes().to_vec(),
            Frame::SendPacket { dst, payload } => {
                let mut b = Vec::with_capacity(KEY_LEN + payload.len());
                b.extend_from_slice(dst);
                b.extend_from_slice(payload);
                b
            }
            Frame::RecvPacket { src, payload } => {
                let mut b = Vec::with_capacity(KEY_LEN + payload.len());
                b.extend_from_slice(src);
                b.extend_from_slice(payload);
                b
            }
            Frame::Ping { data } | Frame::Pong { data } => data.to_vec(),
            Frame::PeerGone { pubkey } => pubkey.to_vec(),
            Frame::Health | Frame::Restarting => Vec::new(),
        }
    }

    /// Encode a single frame to bytes (`[type][len][body]`).
    pub fn encode(&self) -> Vec<u8> {
        let body = self.body();
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(self.type_byte());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode the first frame in `buf`, returning it and the number of bytes
    /// consumed (so callers can decode a stream of frames).
    pub fn decode(buf: &[u8]) -> Result<(Frame, usize), Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::ShortBuffer {
                need: HEADER_LEN,
                have: buf.len(),
            });
        }
        let ty = buf[0];
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if len > MAX_PACKET_SIZE + KEY_LEN {
            return Err(Error::TooLarge(len));
        }
        let total = HEADER_LEN + len;
        if buf.len() < total {
            return Err(Error::ShortBuffer {
                need: total,
                have: buf.len(),
            });
        }
        let body = &buf[HEADER_LEN..total];

        let frame = match ty {
            T_CLIENT_INFO => {
                if body.len() != KEY_LEN + 4 {
                    return Err(Error::BadLength(body.len()));
                }
                Frame::ClientInfo {
                    pubkey: key(body)?,
                    protocol_version: be_u32(&body[KEY_LEN..])?,
                }
            }
            T_SERVER_INFO => {
                if body.len() != 4 {
                    return Err(Error::BadLength(body.len()));
                }
                Frame::ServerInfo {
                    protocol_version: be_u32(body)?,
                }
            }
            T_SEND_PACKET | T_RECV_PACKET => {
                if body.len() < KEY_LEN {
                    return Err(Error::BadLength(body.len()));
                }
                let payload = body[KEY_LEN..].to_vec();
                if payload.len() > MAX_PACKET_SIZE {
                    return Err(Error::TooLarge(payload.len()));
                }
                let k = key(body)?;
                if ty == T_SEND_PACKET {
                    Frame::SendPacket { dst: k, payload }
                } else {
                    Frame::RecvPacket { src: k, payload }
                }
            }
            T_PING | T_PONG => {
                if body.len() != 8 {
                    return Err(Error::BadLength(body.len()));
                }
                let mut d = [0u8; 8];
                d.copy_from_slice(body);
                if ty == T_PING {
                    Frame::Ping { data: d }
                } else {
                    Frame::Pong { data: d }
                }
            }
            T_PEER_GONE => {
                if body.len() != KEY_LEN {
                    return Err(Error::BadLength(body.len()));
                }
                Frame::PeerGone { pubkey: key(body)? }
            }
            T_HEALTH => Frame::Health,
            T_RESTARTING => Frame::Restarting,
            other => return Err(Error::UnknownType(other)),
        };
        Ok((frame, total))
    }
}

fn key(b: &[u8]) -> Result<PublicKey, Error> {
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(b.get(..KEY_LEN).ok_or(Error::BadLength(b.len()))?);
    Ok(k)
}

fn be_u32(b: &[u8]) -> Result<u32, Error> {
    let s = b.get(..4).ok_or(Error::BadLength(b.len()))?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod test {
    use super::*;

    fn roundtrip(f: Frame) {
        let bytes = f.encode();
        let (decoded, n) = Frame::decode(&bytes).expect("decode");
        assert_eq!(decoded, f);
        assert_eq!(n, bytes.len());
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(Frame::ClientInfo {
            pubkey: [7u8; 32],
            protocol_version: 1,
        });
        roundtrip(Frame::ServerInfo { protocol_version: 1 });
        roundtrip(Frame::SendPacket {
            dst: [1u8; 32],
            payload: vec![9, 8, 7],
        });
        roundtrip(Frame::RecvPacket {
            src: [2u8; 32],
            payload: vec![],
        });
        roundtrip(Frame::Ping {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        });
        roundtrip(Frame::Pong {
            data: [8, 7, 6, 5, 4, 3, 2, 1],
        });
        roundtrip(Frame::PeerGone { pubkey: [3u8; 32] });
        roundtrip(Frame::Health);
        roundtrip(Frame::Restarting);
    }

    #[test]
    fn decodes_consecutive_frames() {
        let mut buf = Frame::Health.encode();
        buf.extend(Frame::Ping { data: [0; 8] }.encode());
        let (f1, n1) = Frame::decode(&buf).unwrap();
        assert_eq!(f1, Frame::Health);
        let (f2, n2) = Frame::decode(&buf[n1..]).unwrap();
        assert_eq!(f2, Frame::Ping { data: [0; 8] });
        assert_eq!(n1 + n2, buf.len());
    }

    #[test]
    fn short_buffer_errors() {
        assert!(matches!(Frame::decode(&[1, 0]), Err(Error::ShortBuffer { .. })));
        let bytes = Frame::PeerGone { pubkey: [1u8; 32] }.encode();
        assert!(matches!(
            Frame::decode(&bytes[..bytes.len() - 1]),
            Err(Error::ShortBuffer { .. })
        ));
    }

    #[test]
    fn unknown_type_errors() {
        // type 200, len 0
        assert_eq!(Frame::decode(&[200, 0, 0, 0, 0]), Err(Error::UnknownType(200)));
    }

    #[test]
    fn oversized_payload_rejected() {
        let payload = vec![0u8; MAX_PACKET_SIZE + 1];
        let bytes = Frame::SendPacket {
            dst: [0u8; 32],
            payload,
        }
        .encode();
        assert!(matches!(Frame::decode(&bytes), Err(Error::TooLarge(_))));
    }
}
