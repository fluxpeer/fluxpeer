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
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(Box::new(super::Listener { listener, timeout }))
    }

    async fn connect(config: fp_transport::Config) -> Result<fp_transport::SenderAndReceiver, fp_transport::Error> {
        let fp_transport::Config {
            endpoint,
            port,
            timeout,
            ..
        } = config;

        let endpoint = std::net::SocketAddr::new(endpoint, port);
        let stream = tokio::select! {
            stream = tokio::net::TcpStream::connect(endpoint) => stream?,
            _ = tokio::time::sleep(timeout) => {
                return Err(fp_transport::Error::TimeOut(endpoint.ip()));
            }
        };
        crate::split(stream)
    }
}
