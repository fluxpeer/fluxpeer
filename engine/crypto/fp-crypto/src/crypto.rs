pub trait Cryptor: Sized + Send + Sync {
    fn init_handshake(
        own_prikey: crate::x25519::StaticSecret,
        node_pubkey: crate::x25519::PublicKey,
    ) -> Result<(Self, Vec<u8>), crate::Error>;
    fn handle_handshake(
        own_prikey: crate::x25519::StaticSecret,
        own_pubkey: crate::x25519::PublicKey,
        packet: &[u8],
    ) -> Result<(Self, Option<Vec<u8>>), crate::Error>;
    fn handle_handshake_response(&mut self, packet: &[u8]) -> Result<(), crate::Error>;
    fn on_send<'a>(&mut self, packet: &[u8], dst: &'a mut [u8]) -> Result<&'a mut [u8], crate::Error>;
    fn on_recv<'a>(&mut self, packet: &[u8], dst: &'a mut [u8]) -> Result<&'a mut [u8], crate::Error>;

    fn get_peer_public(&self) -> Result<crate::x25519::PublicKey /* peer pubkey */, crate::Error>;

    /// Re-initiate a handshake on an EXISTING session (rekey, initiator side),
    /// keeping the current session live for a gapless transition. Returns the new
    /// handshake-init bytes. Default: unsupported.
    fn rekey_init<'a>(&mut self, _dst: &'a mut [u8]) -> Result<&'a mut [u8], crate::Error> {
        Err(crate::Error::UnexpectedPacket)
    }

    /// Process a rekey handshake-init on an EXISTING session (responder side),
    /// installing the new session alongside the old (kept for in-flight decrypt).
    /// Returns the response to send. Default: unsupported.
    fn rekey_respond<'a>(&mut self, _packet: &[u8], _dst: &'a mut [u8]) -> Result<Option<&'a mut [u8]>, crate::Error> {
        Err(crate::Error::UnexpectedPacket)
    }
}
