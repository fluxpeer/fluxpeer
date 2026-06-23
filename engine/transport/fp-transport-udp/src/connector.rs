#[derive(Debug)]
pub struct Connector {}

#[async_trait::async_trait]
impl fp_transport::Connector for Connector {
    async fn bind(config: fp_transport::Config) -> Result<Box<dyn fp_transport::Listener>, fp_transport::Error> {
        let fp_transport::Config {
            endpoint,
            port,
            timeout,
            ..
        } = config;
        let addr = std::net::SocketAddr::new(endpoint, port);
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        Ok(Box::new(super::Listener::new(socket, timeout)))
    }

    async fn connect(config: fp_transport::Config) -> Result<fp_transport::SenderAndReceiver, fp_transport::Error> {
        let fp_transport::Config {
            endpoint,
            port,
            timeout,
            ..
        } = config;
        let bind_addr: std::net::SocketAddr = if endpoint.is_ipv6() {
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        } else {
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        };
        let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
        let endpoint = std::net::SocketAddr::new(endpoint, port);
        tokio::select! {
            res = sock.connect(endpoint) => res?,
            _ = tokio::time::sleep(timeout) => {
                return Err(fp_transport::Error::TimeOut(endpoint.ip()));
            }
        };
        crate::split(sock)
    }
}
