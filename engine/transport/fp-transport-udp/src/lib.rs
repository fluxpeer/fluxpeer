pub mod connector;
pub use connector::Connector;

pub mod listener;
pub use listener::Listener;

pub mod transport;
pub use transport::{ChannelReceiver, Receiver, Sender};

fn set_socket(socket: socket2::Socket) -> Result<socket2::Socket, fp_transport::Error> {
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.set_keepalive(true)?;
    Ok(socket)
}

pub(crate) fn split(socket: tokio::net::UdpSocket) -> Result<fp_transport::SenderAndReceiver, fp_transport::Error> {
    let socket = set_socket(socket.into_std()?.into())?;
    let socket = tokio::net::UdpSocket::from_std(socket.into())?;
    let socket = std::sync::Arc::new(socket);
    Ok((
        Box::new(crate::Sender {
            sink: Some(socket.clone()),
        }),
        Box::new(crate::Receiver { stream: Some(socket) }),
    ))
}

pub fn version() -> std::collections::HashMap<String, String> {
    let mut version: std::collections::HashMap<_, _> = fp_transport::version()
        .into_iter()
        .map(|(k, v)| (format!("fp-transport-udp:{k}"), v))
        .collect();
    version.insert("fp-transport-udp".to_string(), env!("CARGO_PKG_VERSION").to_string());
    version
}

#[cfg(test)]
mod test {
    #[test]
    fn version() {
        println!("{:#?}", crate::version());
    }
}
