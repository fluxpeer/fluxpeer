/// UDP sender that writes datagrams via `send_to` on a shared socket.
pub struct Sender {
    pub(crate) sink: Option<std::sync::Arc<tokio::net::UdpSocket>>,
}

#[async_trait::async_trait]
impl fp_transport::TransportSender for Sender {
    async fn send(&mut self, pkt: Vec<u8>) -> Result<(), fp_transport::Error> {
        let socket = self
            .sink
            .as_ref()
            .ok_or_else(|| fp_transport::Error::UnexpectedResult("sender closed".into()))?;
        socket.send(&pkt).await.map(|_| ())?;
        Ok(())
    }

    async fn close(&mut self) {
        // Drop the Arc handle; UDP is connectionless so dropping is sufficient.
        self.sink.take();
    }
}

/// UDP receiver backed by an mpsc channel fed by a dispatcher task.
pub struct ChannelReceiver {
    pub(crate) rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

#[async_trait::async_trait]
impl fp_transport::TransportReceiver for ChannelReceiver {
    async fn recv(&mut self) -> Result<Vec<u8>, fp_transport::Error> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| fp_transport::Error::UnexpectedResult("receiver channel closed".into()))
    }

    async fn close(&mut self) {
        self.rx.close();
    }
}

/// UDP receiver that reads directly from a socket (used by the client-side connector).
pub struct Receiver {
    pub(crate) stream: Option<std::sync::Arc<tokio::net::UdpSocket>>,
}

#[async_trait::async_trait]
impl fp_transport::TransportReceiver for Receiver {
    async fn recv(&mut self) -> Result<Vec<u8>, fp_transport::Error> {
        let socket = self
            .stream
            .as_ref()
            .ok_or_else(|| fp_transport::Error::UnexpectedResult("receiver closed".into()))?;
        let mut buf = vec![0u8; 65535];
        let n = socket.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn close(&mut self) {
        // Drop the Arc handle; UDP is connectionless so dropping is sufficient.
        self.stream.take();
    }
}
