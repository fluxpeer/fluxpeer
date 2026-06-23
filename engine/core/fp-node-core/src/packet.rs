const HEARTBEAT: u8 = 0;
const HANDSHAKE: u8 = 1;
const TOGGLE_CRYPTOR: u8 = 2;
const TOGGLE_TRANSPORT: u8 = 3;
const DISCONNECT: u8 = 4;
const DATA: u8 = 5;

pub enum Packet {
    Heartbeat(Vec<u8>),
    Handshake(Handshake),
    ToggleCryptor(Handshake),
    ToggleTransport(ToggleTransport),
    Disconnect(DisconnectReason),
    Data(Vec<u8>),
}

impl TryFrom<Vec<u8>> for Packet {
    type Error = crate::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let mut value: std::collections::VecDeque<u8> = value.into();
        let flag = value.pop_front().ok_or(crate::Error::InvalidPacket)?;
        let pkt: Vec<u8> = value.into();

        match flag {
            HEARTBEAT => Ok(Self::Heartbeat(pkt)),
            HANDSHAKE => Ok(serde_json::from_slice(&pkt).map(Self::Handshake)?),
            TOGGLE_CRYPTOR => Ok(serde_json::from_slice(&pkt).map(Self::ToggleCryptor)?),
            TOGGLE_TRANSPORT => Ok(serde_json::from_slice(&pkt).map(Self::ToggleTransport)?),
            DISCONNECT => Ok(serde_json::from_slice(&pkt).map(Self::Disconnect)?),
            DATA => Ok(Self::Data(pkt)),
            _ => Err(crate::Error::InvalidPacket),
        }
    }
}

impl TryFrom<Packet> for Vec<u8> {
    type Error = crate::Error;

    fn try_from(value: Packet) -> Result<Self, Self::Error> {
        let flag;
        let mut pkt: std::collections::VecDeque<u8> = match value {
            Packet::Heartbeat(pkt) => {
                flag = HEARTBEAT;
                pkt.into()
            }
            Packet::Handshake(ref handshake) => {
                flag = HANDSHAKE;
                serde_json::to_vec(handshake)?.into()
            }
            Packet::ToggleCryptor(ref toggle_cryptor) => {
                flag = TOGGLE_CRYPTOR;
                serde_json::to_vec(toggle_cryptor)?.into()
            }
            Packet::ToggleTransport(ref toggle_transport) => {
                flag = TOGGLE_TRANSPORT;
                serde_json::to_vec(toggle_transport)?.into()
            }
            Packet::Disconnect(ref disconnect) => {
                flag = DISCONNECT;
                serde_json::to_vec(disconnect)?.into()
            }
            Packet::Data(data) => {
                flag = DATA;
                data.into()
            }
        };
        pkt.push_front(flag);
        Ok(pkt.into())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Handshake {
    pub cryptor: String,
    pub auth_packet: Vec<u8>,
    /// Data-plane protocol version advertised by the initiator (see
    /// [`crate::protocol`]). `#[serde(default)]` tolerates peers that predate
    /// versioning (deserializes to `PROTOCOL_VERSION_UNKNOWN`).
    #[serde(default)]
    pub protocol_version: u32,
}

impl From<Handshake> for Packet {
    fn from(value: Handshake) -> Self {
        Self::Handshake(value)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DisconnectReason {
    pub code: u16,
    pub reason: String,
}

impl From<DisconnectReason> for Packet {
    fn from(value: DisconnectReason) -> Self {
        Self::Disconnect(value)
    }
}

impl From<crate::Error> for DisconnectReason {
    fn from(value: crate::Error) -> Self {
        Self {
            code: 0,
            reason: value.to_string(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ToggleTransport {
    port: u16,
    protocol: String,
}

impl From<ToggleTransport> for Packet {
    fn from(value: ToggleTransport) -> Self {
        Self::ToggleTransport(value)
    }
}
