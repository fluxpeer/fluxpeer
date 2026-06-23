#![allow(clippy::too_many_arguments)]

mod packet;
pub use packet::{DisconnectReason, Handshake, Packet, ToggleTransport};

pub mod error;
pub use error::Error;

pub mod protocol;

pub mod allowed_ip;
pub use allowed_ip::AllowedIP;

pub mod ip_table;
pub use ip_table::IpTable;

pub mod iface;
pub use iface::Iface;

pub mod peer;
pub use peer::Inner as PeerInner;

pub mod key;

pub type TransportSender = Box<dyn fp_transport::TransportSender>;
pub type TransportReceiver = Box<dyn fp_transport::TransportReceiver>;
pub type TokioUnboundedSender<T> = tokio::sync::mpsc::UnboundedSender<T>;
pub type TransportCallback = extern "C" fn(data: *const libc::c_char, error_message: *const libc::c_char);
pub type CallBack = TokioUnboundedSender<Result<Option<serde_json::Value>, crate::Error>>;

/// Re-export of the RawCryptor types
pub use fp_crypto::RawCryptor;

/// Re-export of the RawConnector types
pub use fp_transport::RawConnector;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use fp_crypto::x25519::{EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret};
}

pub const MAX_PACKET_SIZE: usize = (1 << 16) - 1;

pub fn version() -> std::collections::HashMap<String, String> {
    let mut version: std::collections::HashMap<_, _> = fp_transport::version()
        .into_iter()
        .map(|(k, v)| (format!("fp-node-core:{k}"), v))
        .collect();
    version.insert("fp-node-core".to_string(), env!("CARGO_PKG_VERSION").to_string());
    for (k, v) in fp_crypto::version().into_iter() {
        version.insert(format!("fp-node-core:{k}"), v);
    }
    version
}

#[cfg(test)]
mod test {
    #[test]
    fn version() {
        println!("{:#?}", crate::version());
    }
}
