// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
pub mod crypto;
pub use crypto::{Cryptor, peek_init_pubkey};

/// Domain-separation label so the disco MAC subkey can never collide with the
/// Noise handshake's own use of the same static-static DH secret.
const DISCO_MAC_LABEL: &[u8] = b"fluxpeer-disco-mac-v1";

/// Authenticate a fluxpeer disco datagram (a NAT-traversal ping/pong), which is
/// exchanged BEFORE the wg session exists. Keyed by the two peers' static-static DH
/// secret — symmetric and available as soon as both static public keys are known —
/// so an off-path attacker can't forge a disco message that redirects a peer's path.
/// Returns a 16-byte tag. Both peers derive the same key, hence the same tag.
pub fn disco_mac(static_shared: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let subkey = handshake::b2s_hmac(static_shared, DISCO_MAC_LABEL);
    handshake::b2s_keyed_mac_16(&subkey, data)
}

pub(crate) mod noise;
use noise::{HandshakeInit, HandshakeResponse, Noise, NoiseResult, Packet, PacketData};

pub(crate) mod handshake;
use handshake::Handshake;

pub(crate) mod verifier;
pub(crate) use verifier::Verifier;

mod session;
use session::Session;

mod sleepyinstant;

pub(crate) mod x25519 {
    pub(crate) use x25519_dalek::{PublicKey, ReusableSecret, SharedSecret, StaticSecret};
}

/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
// const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
/// Maximum overhead added to a payload when encrypting a data packet:
/// 16 (header: type + index + counter) + 1 (pad_len byte) + 15 (max random padding) + 16 (AEAD tag) = 48
const DATA_OVERHEAD_SZ: usize = 48;

/// Minimum valid data packet size on the wire:
/// 16 (header) + 1 (pad_len byte, encrypted) + 16 (AEAD tag) = 33
const DATA_MIN_SZ: usize = 33;

pub fn version() -> std::collections::HashMap<String, String> {
    let mut version: std::collections::HashMap<_, _> = fp_crypto::version()
        .into_iter()
        .map(|(k, v)| (format!("fp-crypto-noise:{k}"), v))
        .collect();
    version.insert("fp-crypto-noise".to_string(), env!("CARGO_PKG_VERSION").to_string());
    version
}

#[cfg(test)]
mod test {
    #[test]
    fn version() {
        println!("{:#?}", crate::version());
    }
}
