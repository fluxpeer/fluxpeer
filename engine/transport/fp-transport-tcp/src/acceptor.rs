//! `TcpAcceptor`: the reusable "process one already-established TcpStream" unit
//! for the plain-TCP transport.
//!
//! It splits an externally-supplied `TcpStream` into a length-prefixed
//! `Codec`-framed sender/receiver, reads the first frame (with a bounded
//! timeout and cancellation support), and produces an `AcceptResponse`. This is
//! shared between the per-port TCP `Listener` and the demux listener so both
//! decode the wire format identically from byte 0.

use std::net::IpAddr;

/// Process an already-established TcpStream: split + Codec + read first frame.
///
/// `closer` cancels the in-flight first-frame read (listener shutdown).
/// `timeout` bounds how long to wait for the first frame before giving up,
/// mirroring the per-port listener's behaviour so a silent peer cannot wedge it.
pub async fn accept_established_stream(
    stream: tokio::net::TcpStream,
    peer_addr: IpAddr,
    addr_for_timeout: IpAddr,
    timeout: std::time::Duration,
    closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
) -> Result<fp_transport::AcceptResponse, fp_transport::Error> {
    let (sender, mut receiver) = crate::split(stream)?;
    let packet = tokio::select! {
        packet = receiver.recv() => packet?,
        _ = closer.recv() => {
            return Err(fp_transport::Error::ListenerHasBeenClosed);
        },
        _ = tokio::time::sleep(timeout) => {
            return Err(fp_transport::Error::TimeOut(addr_for_timeout));
        },
    };

    Ok(fp_transport::AcceptResponse {
        packet,
        sender,
        receiver,
        peer_addr,
    })
}

#[cfg(test)]
mod test {
    use super::accept_established_stream;
    use bytes::BufMut as _;
    use tokio::io::AsyncWriteExt as _;

    /// An already-established TcpStream carrying one length-prefixed frame must
    /// be decoded into an AcceptResponse with the framed payload — verifying the
    /// extracted acceptor does not regress the per-port path's wire handling.
    #[tokio::test]
    async fn accepts_first_frame_from_established_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut buf = bytes::BytesMut::new();
            buf.put_u32(3);
            buf.put_slice(&[0x00, 0x11, 0x22]);
            sock.write_all(&buf).await.unwrap();
            sock.flush().await.unwrap();
            // Keep the socket open until the server has read.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let (stream, peer) = listener.accept().await.unwrap();
        let (_tx, mut closer) = tokio::sync::mpsc::unbounded_channel();
        let resp = accept_established_stream(
            stream,
            peer.ip(),
            peer.ip(),
            std::time::Duration::from_secs(2),
            &mut closer,
        )
        .await
        .unwrap();

        assert_eq!(resp.packet, vec![0x00, 0x11, 0x22]);
        client.await.unwrap();
    }
}
