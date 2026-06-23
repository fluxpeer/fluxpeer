pub(crate) type TcpFramed = tokio_util::codec::Framed<tokio::net::TcpStream, crate::Codec>;

pub struct Sender {
    pub(crate) sink: futures::stream::SplitSink<TcpFramed, Vec<u8>>,
}

#[async_trait::async_trait]
impl fp_transport::TransportSender for Sender {
    async fn send(&mut self, pkt: Vec<u8>) -> Result<(), fp_transport::Error> {
        use futures::SinkExt as _;
        self.sink.send(pkt).await
    }

    async fn close(&mut self) {
        use futures::SinkExt as _;
        let _ = self.sink.close().await;
    }
}

pub struct Receiver {
    pub(crate) stream: futures::stream::SplitStream<TcpFramed>,
}

#[async_trait::async_trait]
impl fp_transport::TransportReceiver for Receiver {
    async fn recv(&mut self) -> Result<Vec<u8>, fp_transport::Error> {
        use futures::StreamExt as _;
        match self.stream.next().await {
            Some(pkt) => pkt,
            None => Err(fp_transport::Error::UnexpectedResult("stream closed".into())),
        }
    }

    async fn close(&mut self) {
        //
    }
}
