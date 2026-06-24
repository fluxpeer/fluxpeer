mod error;
pub use error::Error;

mod connector;
pub use connector::{AcceptResponse, Connector, Listener, SenderAndReceiver, TransportReceiver, TransportSender};

mod raw_connector;
pub use raw_connector::RawConnector;

mod protect;
pub use protect::{connect_tcp, protect_fd};
#[cfg(unix)]
pub use protect::{ProtectFn, set_protect};

pub enum Event {
    Send(Vec<u8>),
    Close,
}

pub struct Config {
    pub endpoint: std::net::IpAddr,
    pub port: u16,
    pub timeout: std::time::Duration,
    pub tls: Option<String>,
}

pub fn version() -> std::collections::HashMap<String, String> {
    let mut v = std::collections::HashMap::new();
    v.insert("fp-transport".to_string(), env!("CARGO_PKG_VERSION").to_string());
    v
}

#[cfg(test)]
mod test {
    #[test]
    fn version() {
        println!("{:#?}", crate::version());
    }
}
