#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("key not set")]
    KeyNotSet,
    #[error("unauthorized")]
    Unauthorized,
    #[error("no worker")]
    NoWorker,
    #[error("`{0}` worker mailbox error")]
    WorkerMailboxError(String),
    #[error("port `{0}` not open: listener list: `{1:#?}`")]
    PortNotOpen(u16, std::collections::HashMap<String, Vec<u16>>),
    #[error("Iface not set")]
    IfaceNotSet,
    #[error("Iface send failed")]
    IfaceSendFailed,
    #[error("all ip has been allocated")]
    AllIpHasBeenAllocated,
    #[error("ip is empty")]
    IPIsEmpty,
    #[error("peer not exist")]
    PeerNotExist,
    #[error("peer transport not exist")]
    PeerTransportNotExist,
    #[error("peer cryptor not exist")]
    PeerCryptorNotExist,
    #[error("all port has been allocated")]
    AllPortHasBeenAllocated,
    #[error("verify packet error")]
    InvalidPacket,
    #[error("unexpected result: `{0}`")]
    UnexpectedResult(String),
    #[error("new listener failed: `{0}`")]
    NewListenerFailed(String),

    #[error("assign iface failed: `{0}`")]
    AssignIfaceFailed(String),
    #[error("resources not exist: `{0}`")]
    ResourcesNotExist(String),

    #[error("transport error: `{0}`")]
    TransportError(String),

    #[error("callback unavailable")]
    CallbackUnavailable,
    #[error("Json error: `{0}`")]
    Json(String),
    #[error("Tun error: `{0}`")]
    Tun(String),
    #[error("crypto error: `{0}`")]
    CryptoFailed(#[from] fp_crypto::Error),
}

impl From<fp_transport::Error> for Error {
    fn from(value: fp_transport::Error) -> Self {
        Self::TransportError(value.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value.to_string())
    }
}

impl From<fp_tun::Error> for Error {
    fn from(value: fp_tun::Error) -> Self {
        Self::Tun(value.to_string())
    }
}

impl<T> From<tokio::sync::mpsc::error::SendError<T>> for Error {
    fn from(_: tokio::sync::mpsc::error::SendError<T>) -> Self {
        Self::CallbackUnavailable
    }
}
