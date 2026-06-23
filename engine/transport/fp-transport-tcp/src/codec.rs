use bytes::BufMut;

pub struct Codec;

const LENGTH_SIZE: usize = 4;
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

impl tokio_util::codec::Encoder<Vec<u8>> for Codec {
    type Error = fp_transport::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        if item.len() > MAX_FRAME_SIZE {
            return Err(fp_transport::Error::UnexpectedResult(format!(
                "frame size {} exceeds maximum {}",
                item.len(),
                MAX_FRAME_SIZE
            )));
        }
        dst.reserve(LENGTH_SIZE + item.len());

        let len = item.len() as u32;
        dst.put_u32(len);
        dst.extend_from_slice(item.as_slice());
        Ok(())
    }
}

impl tokio_util::codec::Encoder<&[u8]> for Codec {
    type Error = fp_transport::Error;

    fn encode(&mut self, item: &[u8], dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        if item.len() > MAX_FRAME_SIZE {
            return Err(fp_transport::Error::UnexpectedResult(format!(
                "frame size {} exceeds maximum {}",
                item.len(),
                MAX_FRAME_SIZE
            )));
        }
        dst.reserve(LENGTH_SIZE + item.len());

        let len = item.len() as u32;
        dst.put_u32(len);
        dst.extend_from_slice(item);
        Ok(())
    }
}

impl tokio_util::codec::Decoder for Codec {
    type Item = Vec<u8>;

    type Error = fp_transport::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let src_len = src.len();

        if src_len <= 4 {
            // Not enough data to read header marker.
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[0..=3]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > MAX_FRAME_SIZE {
            return Err(fp_transport::Error::UnexpectedResult(format!(
                "frame size {} exceeds maximum {}",
                length, MAX_FRAME_SIZE
            )));
        }

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
mod test {
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
