pub type SenderAndReceiver = (Box<dyn crate::TransportSender>, Box<dyn crate::TransportReceiver>);

pub struct AcceptResponse {
    pub packet: Vec<u8>,
    pub sender: Box<dyn crate::TransportSender>,
    pub receiver: Box<dyn crate::TransportReceiver>,
    pub peer_addr: std::net::IpAddr,
}

#[async_trait::async_trait]
pub trait Connector: Send + Sync {
    async fn bind(config: crate::Config) -> Result<Box<dyn Listener>, crate::Error>; // Bind with port
    async fn connect(config: crate::Config) -> Result<SenderAndReceiver, crate::Error>; // Connect to endpoint
}

#[async_trait::async_trait]
pub trait Listener: Send + Sync {
    async fn accept(
        &self,
        closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    ) -> Result<AcceptResponse, crate::Error>;
}

#[async_trait::async_trait]
pub trait TransportSender: Send + Sync {
    async fn send(&mut self, pkt: Vec<u8>) -> Result<(), crate::Error>;
    async fn close(&mut self);
}

#[async_trait::async_trait]
pub trait TransportReceiver: Send + Sync {
    async fn recv(&mut self) -> Result<Vec<u8>, crate::Error>;
    async fn close(&mut self);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Error;

    use bytes::BufMut;

    pub struct Codec;

    const LENGTH_SIZE: usize = 4;

    impl tokio_util::codec::Encoder<Vec<u8>> for Codec {
        type Error = Error;

        fn encode(&mut self, item: Vec<u8>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
            dst.reserve(LENGTH_SIZE + item.len());

            let len = item.len() as u32;
            dst.put_u32(len);
            dst.extend_from_slice(item.as_slice());
            Ok(())
        }
    }

    impl tokio_util::codec::Decoder for Codec {
        type Item = Vec<u8>;

        type Error = Error;

        fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            let src_len = src.len();

            if src_len <= 4 {
                // Not enough data to read header marker.
                return Ok(None);
            }

            let mut length_bytes = [0u8; 4];
            length_bytes.copy_from_slice(&src[0..=3]);
            let length = u32::from_be_bytes(length_bytes) as usize;

            if (src_len) < 4 + length {
                // Not enough data to read length marker.
                src.reserve(4 + length - src.len());

                return Ok(None);
            }

            let dst = src[4..(4 + length)].to_vec();
            use bytes::Buf as _;
            src.advance(4 + length);
            Ok(Some(dst))
        }
    }

    #[cfg(test)]
    mod codec_test {
        use super::Codec;
        use bytes::BufMut;
        use tokio_util::codec::{Decoder, Encoder};

        #[test]
        fn decode() {
            let mut src = bytes::BytesMut::new();
            src.put_u32(3);
            src.put_slice(&[9, 8, 7]);
            let dst = vec![9, 8, 7];
            let decode = Codec.decode(&mut src).unwrap().unwrap();

            assert_eq!(dst, decode);
        }

        #[test]
        fn encode() {
            let mut src = bytes::BytesMut::new();
            src.put_u32(3);
            src.put_slice(&[9, 8, 7]);

            let mut encode = bytes::BytesMut::new();

            Codec.encode([9, 8, 7].to_vec(), &mut encode).unwrap();

            assert_eq!(encode, src);
        }
    }
}
