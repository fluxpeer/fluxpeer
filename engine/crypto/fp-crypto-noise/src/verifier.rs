use crate::handshake::LABEL_MAC1;
use crate::handshake::{b2s_hash, b2s_keyed_mac_16};
use crate::{HandshakeInit, HandshakeResponse, Noise, Packet};
use rand_core::{OsRng, RngCore};
#[allow(deprecated)]
use ring::constant_time::verify_slices_are_equal;

/// There are two places where WireGuard requires "randomness" for cookies:
///
/// * The 24 byte nonce in the cookie massage - here the only goal is to avoid nonce reuse
/// * A secret value that changes every two minutes
///
/// Because the main goal of the cookie is simply for a party to prove ownership of an IP address
/// we can relax the randomness definition a bit, in order to avoid locking, because using less
/// resources is the main goal of any DoS prevention mechanism.
/// In order to avoid locking and calls to rand we derive pseudo random values using the AEAD and
/// some counters.
///
/// Remove cookies & rate limit now.
pub(crate) struct Verifier {
    mac1_key: [u8; 32],
}

impl Verifier {
    pub(crate) fn new(public_key: &crate::x25519::PublicKey) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        Verifier {
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
        }
    }

    /// Verify the MAC fields on the datagram, and apply rate limiting if needed
    pub(crate) fn verify_packet<'a>(&self, src: &'a [u8]) -> Result<Packet<'a>, fp_crypto::Error> {
        let packet = Noise::parse_incoming_packet(src)?;

        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit { .. }) | Packet::HandshakeResponse(HandshakeResponse { .. }) =
            packet
        {
            let (msg, macs) = src.split_at(src.len() - 32);
            let (mac1, _mac2) = macs.split_at(16);

            tracing::info!("[verify_packet] handle handshake");

            let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
            #[allow(deprecated)]
            verify_slices_are_equal(&computed_mac1[..16], mac1).map_err(|_| fp_crypto::Error::InvalidMac)?;
        }

        Ok(packet)
    }
}
