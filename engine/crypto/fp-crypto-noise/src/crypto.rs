const HANDSHAKE_INIT_SZ: usize = 148;

/// Per-process counter for the 24-bit PEER index (high bits of a session's
/// `local_index`; the low 8 bits are the cyclic per-peer session counter). It
/// MUST be unique across a node's peers: a node routes inbound packets by the
/// session index through one shared `index_map`, so if two peers shared the same
/// high bits their indices would collide → packets misroute to the wrong peer →
/// wrong-key decrypt (InvalidAeadTag). A hardcoded constant here silently breaks
/// every multi-peer mesh while 2-node tests pass.
static PEER_INDEX: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Next unique session base index: a fresh 24-bit peer id in the high bits, 0 in
/// the low (session-counter) byte.
fn next_session_base() -> u32 {
    (PEER_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 0x00ff_ffff) << 8
}

pub struct Cryptor {
    noise: crate::Noise,
}

impl fp_crypto::Cryptor for Cryptor {
    fn init_handshake(
        own_prikey: fp_crypto::x25519::StaticSecret,
        node_pubkey: fp_crypto::x25519::PublicKey,
    ) -> Result<(Cryptor, Vec<u8>), fp_crypto::Error> {
        let mut auth_packet: [u8; HANDSHAKE_INIT_SZ] = [0u8; HANDSHAKE_INIT_SZ];

        let public_key = crate::x25519::PublicKey::from(&own_prikey);
        let rate_limiter = crate::Verifier::new(&public_key);
        let noise = crate::Noise::new(own_prikey, node_pubkey, None, next_session_base(), Some(rate_limiter));
        let mut crypro = Cryptor { noise };
        let packet = crypro
            .noise
            .handshake
            .format_handshake_initiation(&mut auth_packet[..])?
            .to_vec();

        Ok((crypro, packet))
    }

    fn handle_handshake(
        own_prikey: fp_crypto::x25519::StaticSecret,
        own_pubkey: fp_crypto::x25519::PublicKey,
        packet: &[u8],
    ) -> Result<(Cryptor, Option<Vec<u8>>), fp_crypto::Error> {
        let mut buf: [u8; HANDSHAKE_INIT_SZ] = [0u8; HANDSHAKE_INIT_SZ];

        let verifier = crate::Verifier::new(&own_pubkey);
        let packet = match verifier.verify_packet(packet) {
            Ok(packet) => packet,
            Err(_e) => {
                return Err(fp_crypto::Error::InvalidMac);
            }
        };

        let pkey = if let crate::Packet::HandshakeInit(p) = &packet {
            let pkey = crate::handshake::parse_handshake_anon(&own_prikey, &own_pubkey, p)?.peer_static_public;
            crate::x25519::PublicKey::from(pkey)
        } else {
            return Err(fp_crypto::Error::InvalidPacket);
        };

        let mut noise = crate::Noise::new(own_prikey, pkey, None, next_session_base(), Some(verifier));

        let response = match noise.handle_verified_packet(packet, &mut buf[..])? {
            crate::NoiseResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            _ => None,
        };
        let crypto = Self { noise };

        Ok((crypto, response))
    }

    fn handle_handshake_response(&mut self, packet: &[u8]) -> Result<(), fp_crypto::Error> {
        let packet = match crate::noise::Noise::parse_incoming_packet(packet)? {
            crate::noise::Packet::HandshakeResponse(packet) => packet,
            _ => return Err(fp_crypto::Error::UnexpectedPacket),
        };
        self.noise.handle_handshake_response(packet)?;

        Ok(())
    }

    fn on_send<'a>(&mut self, packet: &[u8], dst: &'a mut [u8]) -> Result<&'a mut [u8], fp_crypto::Error> {
        match self.noise.encapsulate(packet, dst)? {
            crate::noise::NoiseResult::WriteToNetwork(pkt) => Ok(pkt),
            _ => Err(fp_crypto::Error::UnexpectedPacket),
        }
    }

    fn on_recv<'a>(&mut self, packet: &[u8], dst: &'a mut [u8]) -> Result<&'a mut [u8], fp_crypto::Error> {
        let parsed_packet = self
            .noise
            .verifier
            .verify_packet(packet)
            .map_err(|_| fp_crypto::Error::UnexpectedPacket)?;

        match self.noise.handle_verified_packet(parsed_packet, &mut dst[..])? {
            crate::NoiseResult::WriteToTunnel(packet, _) => Ok(packet),
            // A keepalive authenticates fine but carries no tunnel payload. Return
            // an empty slice — a *received* packet, NOT an error — so callers can
            // refresh liveness/roaming without forwarding anything to the TUN.
            crate::NoiseResult::Done => Ok(<&mut [u8]>::default()),
            _ => Err(fp_crypto::Error::UnexpectedPacket),
        }
    }

    fn get_peer_public(&self) -> Result<fp_crypto::x25519::PublicKey /* peer pubkey */, fp_crypto::Error> {
        Ok(self.noise.handshake.params.peer_static_public)
    }

    fn rekey_init<'a>(&mut self, dst: &'a mut [u8]) -> Result<&'a mut [u8], fp_crypto::Error> {
        // Re-initiate on the same Noise: the handshake state moves current→previous
        // (receive_handshake_response checks both), and the live session keeps
        // encrypting until handle_handshake_response installs the new one.
        self.noise.handshake.format_handshake_initiation(dst)
    }

    fn rekey_respond<'a>(
        &mut self,
        packet: &[u8],
        dst: &'a mut [u8],
    ) -> Result<Option<&'a mut [u8]>, fp_crypto::Error> {
        let parsed = self
            .noise
            .verifier
            .verify_packet(packet)
            .map_err(|_| fp_crypto::Error::UnexpectedPacket)?;
        // Processing the init on the EXISTING Noise derives a NEW session into a
        // fresh slot (N_SESSIONS rotation) and makes it current; the old session
        // stays in its slot to decrypt in-flight data until the peer switches.
        match self.noise.handle_verified_packet(parsed, dst)? {
            crate::NoiseResult::WriteToNetwork(resp) => Ok(Some(resp)),
            _ => Ok(None),
        }
    }
}

/// Peek the initiator's static pubkey from a handshake-init WITHOUT consuming it
/// (no state advance) — lets the responder route a rekey init to the right peer's
/// existing session before deciding to rekey-in-place vs. start fresh.
pub fn peek_init_pubkey(
    own_priv: &fp_crypto::x25519::StaticSecret,
    own_pub: &fp_crypto::x25519::PublicKey,
    packet: &[u8],
) -> Option<[u8; 32]> {
    let verifier = crate::Verifier::new(own_pub);
    let parsed = verifier.verify_packet(packet).ok()?;
    if let crate::Packet::HandshakeInit(p) = &parsed {
        crate::handshake::parse_handshake_anon(own_priv, own_pub, p)
            .ok()
            .map(|h| h.peer_static_public)
    } else {
        None
    }
}
