use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::IpAddr;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;

#[derive(Debug)]
pub(crate) enum NoiseResult<'a> {
    Done,
    // Err(fp_crypto::Error),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnel(&'a mut [u8], #[allow(dead_code)] IpAddr),
}

/// Tunnel represents a point-to-point WireGuard connection
pub(crate) struct Noise {
    /// The handshake currently in progress
    pub(crate) handshake: crate::Handshake,
    /// The crate::N_SESSIONS most recent sessions, index is session id modulo crate::N_SESSIONS
    sessions: [Option<crate::Session>; crate::N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    // verify packet
    pub(crate) verifier: crate::Verifier,
}

#[derive(Debug)]
pub(crate) struct HandshakeInit<'a> {
    pub(crate) sender_idx: u32,
    pub(crate) unencrypted_ephemeral: &'a [u8; 32],
    pub(crate) encrypted_static: &'a [u8],
    pub(crate) encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct HandshakeResponse<'a> {
    pub(crate) sender_idx: u32,
    pub(crate) receiver_idx: u32,
    pub(crate) unencrypted_ephemeral: &'a [u8; 32],
    pub(crate) encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub(crate) struct PacketData<'a> {
    pub(crate) receiver_idx: u32,
    pub(crate) counter: u64,
    pub(crate) encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub(crate) enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    // PacketCookieReply(PacketCookieReply<'a>),
    #[allow(clippy::enum_variant_names)]
    PacketData(PacketData<'a>),
}

impl Noise {
    #[inline(always)]
    pub(crate) fn parse_incoming_packet(src: &[u8]) -> Result<Packet<'_>, fp_crypto::Error> {
        if src.len() < 4 {
            tracing::error!("[parse_incoming_packet] Invalid Packet src.len: {}", src.len());

            return Err(fp_crypto::Error::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().expect("known-safe: length >= 4 checked above"));

        Ok(match (packet_type, src.len()) {
            (crate::HANDSHAKE_INIT, crate::HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(
                    src[4..8]
                        .try_into()
                        .expect("known-safe: HANDSHAKE_INIT_SZ guarantees 148 bytes"),
                ),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("known-safe: HANDSHAKE_INIT_SZ guarantees 148 bytes"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (crate::HANDSHAKE_RESP, crate::HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(
                    src[4..8]
                        .try_into()
                        .expect("known-safe: HANDSHAKE_RESP_SZ guarantees 92 bytes"),
                ),
                receiver_idx: u32::from_le_bytes(
                    src[8..12]
                        .try_into()
                        .expect("known-safe: HANDSHAKE_RESP_SZ guarantees 92 bytes"),
                ),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("known-safe: HANDSHAKE_RESP_SZ guarantees 92 bytes"),
                encrypted_nothing: &src[44..60],
            }),
            (crate::DATA, crate::DATA_MIN_SZ..=std::usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(
                    src[4..8]
                        .try_into()
                        .expect("known-safe: DATA_MIN_SZ guarantees >= 33 bytes"),
                ),
                counter: u64::from_le_bytes(
                    src[8..16]
                        .try_into()
                        .expect("known-safe: DATA_MIN_SZ guarantees >= 33 bytes"),
                ),
                encrypted_encapsulated_packet: &src[16..],
            }),
            _ => {
                tracing::error!(
                    "[Tunn::parse_incoming_packet] unmatch packet_type: {}. len: {}",
                    packet_type,
                    src.len()
                );
                return Err(fp_crypto::Error::InvalidPacket);
            }
        })
    }

    /// Create a new tunnel using own private key and the peer public key
    pub(crate) fn new(
        static_private: crate::x25519::StaticSecret,
        peer_static_public: crate::x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        index: u32,
        verifier: Option<crate::Verifier>,
    ) -> Self {
        let static_public = crate::x25519::PublicKey::from(&static_private);

        Noise {
            handshake: crate::Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index << 8,
                preshared_key,
            ),
            sessions: Default::default(),
            current: Default::default(),
            packet_queue: VecDeque::new(),

            verifier: verifier.unwrap_or_else(|| crate::Verifier::new(&static_public)),
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub(crate) fn encapsulate<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % crate::N_SESSIONS] {
            // Send the packet using an established session
            let packet = session.format_packet_data(src, dst)?;
            return Ok(NoiseResult::WriteToNetwork(packet));
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst)
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    #[allow(unused)]
    pub(crate) fn decapsulate<'a>(
        &mut self,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        if datagram.is_empty() {
            // Indicates a repeated call
            // return self.send_queued_packet(dst);
        }

        let packet = self.verifier.verify_packet(datagram)?;

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p),
            Packet::PacketData(p) => self.handle_data(p, dst),
        }
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        tracing::debug!(message = "Received handshake_initiation", remote_idx = p.sender_idx);

        let (packet, session) = self.handshake.receive_handshake_initialization(p, dst)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % crate::N_SESSIONS] = Some(session);

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(NoiseResult::WriteToNetwork(packet))
    }

    pub(crate) fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
    ) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % crate::N_SESSIONS;
        self.sessions[index] = Some(session);

        self.set_current_session(l_idx);

        Ok(NoiseResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % crate::N_SESSIONS].is_none() {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(&mut self, packet: PacketData, dst: &'a mut [u8]) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % crate::N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_mut();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                fp_crypto::Error::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.validate_decapsulated_packet(decapsulated_packet)
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub(crate) fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
    ) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        self.handshake.format_handshake_initiation(dst).map(|packet| {
            tracing::debug!("Sending handshake_initiation");
            NoiseResult::WriteToNetwork(packet)
        })
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> Result<NoiseResult<'a>, fp_crypto::Error> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return Ok(NoiseResult::Done), // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .expect("known-safe: IPV4_MIN_HEADER_SIZE guarantees sufficient length");
                let addr_bytes: [u8; IPV4_IP_SZ] = packet[IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .expect("known-safe: IPV4_MIN_HEADER_SIZE guarantees sufficient length");
                (u16::from_be_bytes(len_bytes) as usize, IpAddr::from(addr_bytes))
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .expect("known-safe: IPV6_MIN_HEADER_SIZE guarantees sufficient length");
                let addr_bytes: [u8; IPV6_IP_SZ] = packet[IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .expect("known-safe: IPV6_MIN_HEADER_SIZE guarantees sufficient length");
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return Err(fp_crypto::Error::InvalidPacket),
        };

        if computed_len > packet.len() {
            return Err(fp_crypto::Error::InvalidPacket);
        }

        Ok(NoiseResult::WriteToTunnel(&mut packet[..computed_len], src_ip_address))
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }
}

#[allow(unexpected_cfgs)]
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn create_two_tuns() -> (Noise, Noise) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Noise::new(my_secret_key, their_public_key, None, my_idx, None);

        let their_tun = Noise::new(their_secret_key, my_public_key, None, their_idx, None);

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Noise) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst);
        assert!(matches!(handshake_init, Ok(NoiseResult::WriteToNetwork(_))));
        let handshake_init = if let Ok(NoiseResult::WriteToNetwork(sent)) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Noise, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(handshake_init, &mut dst);
        assert!(matches!(handshake_resp, Ok(NoiseResult::WriteToNetwork(_))));

        let handshake_resp = if let Ok(NoiseResult::WriteToNetwork(sent)) = handshake_resp {
            sent
        } else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Noise, handshake_resp: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(handshake_resp, &mut dst);
        assert!(matches!(keepalive, Ok(NoiseResult::Done)));
    }

    fn create_two_tuns_and_handshake() -> (Noise, Noise) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        parse_handshake_resp(&mut my_tun, &resp);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header = etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Noise::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Noise::parse_incoming_packet(&resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        parse_handshake_resp(&mut my_tun, &resp);
        let packet = Noise::parse_incoming_packet(&resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, Ok(NoiseResult::WriteToNetwork(_))));
        let data = if let Ok(NoiseResult::WriteToNetwork(sent)) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(data, &mut their_dst);
        assert!(matches!(data, Ok(NoiseResult::WriteToTunnel(..))));
        let recv_packet_buf = if let Ok(NoiseResult::WriteToTunnel(recv, _addr)) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }
}
