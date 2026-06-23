#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("no worker")]
    NoWorker,
    #[error("process time out: '{0}'")]
    TimeOut(std::net::IpAddr),
    #[error("listener has been closed")]
    ListenerHasBeenClosed,
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid packet")]
    InvalidPacket,
    #[error("iface send failed")]
    IfaceSendFailed,
    #[error("unexpected result: `{0}`")]
    UnexpectedResult(String),
    #[error("io error: `{0}`")]
    IO(#[from] std::io::Error),
    #[error("channel not work")]
    ChannelNotWork,
}
