pub mod connector;
pub use connector::Connector;

pub mod codec;
pub use codec::Codec;

pub mod acceptor;
pub use acceptor::accept_established_stream;

pub mod listener;
pub use listener::Listener;

pub mod transport;
pub use transport::{Receiver, Sender};

fn set_keepalive(stream: tokio::net::TcpStream) -> Result<tokio::net::TcpStream, fp_transport::Error> {
    let stream = stream.into_std()?;
    let socket = socket2::Socket::from(stream);
    let keep_alive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(20))
        .with_interval(std::time::Duration::from_secs(5));
    socket.set_tcp_keepalive(&keep_alive)?;
    socket.set_nodelay(true)?;
    Ok(tokio::net::TcpStream::from_std(socket.into())?)
}

pub(crate) fn split(stream: tokio::net::TcpStream) -> Result<fp_transport::SenderAndReceiver, fp_transport::Error> {
    let stream = set_keepalive(stream)?;

    use futures::StreamExt as _;
    use tokio_util::codec::Decoder as _;
    let codec = Codec {};
    let framed = codec.framed(stream);

    let (sink, stream) = framed.split();
    Ok((Box::new(crate::Sender { sink }), Box::new(crate::Receiver { stream })))
}

pub fn version() -> std::collections::HashMap<String, String> {
    let mut version: std::collections::HashMap<_, _> = fp_transport::version()
        .into_iter()
        .map(|(k, v)| (format!("fp-transport-tcp:{k}"), v))
        .collect();
    version.insert("fp-transport-tcp".to_string(), env!("CARGO_PKG_VERSION").to_string());
    version
}

#[cfg(test)]
mod test {
    #[test]
    fn version() {
        println!("{:#?}", crate::version());
    }
}
