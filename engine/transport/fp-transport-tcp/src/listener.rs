#[derive(Debug)]
pub struct Listener {
    pub(crate) timeout: std::time::Duration,
    pub(crate) listener: tokio::net::TcpListener,
}

#[async_trait::async_trait]
impl fp_transport::Listener for Listener {
    async fn accept(
        &self,
        closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    ) -> Result<fp_transport::AcceptResponse, fp_transport::Error> {
        let (stream, addr) = self.listener.accept().await?;
        let peer_addr = addr.ip();
        tracing::info!("[fp-transport-tcp] accept new connection: {}", addr);
        // Delegate the split+Codec+first-frame read to the reusable acceptor unit
        // (shared with the demux listener). Identical wire handling, no HOL change.
        crate::acceptor::accept_established_stream(stream, peer_addr, addr.ip(), self.timeout, closer).await
    }
}
