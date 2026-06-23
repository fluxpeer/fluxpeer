//! UDP STUN responder — the relay doubles as STUN. A client
//! sends a magic-prefixed disco `Ping` from the socket it uses for wg, and the
//! server replies `Pong{observed = source addr}`, revealing the client's public
//! (reflexive) `ip:port` behind its NAT so peers can hole-punch to it.

use std::net::SocketAddr;

use fp_disco::Disco;
use tokio::net::UdpSocket;

/// Magic prefix shared with the node's disco datagrams (so the same socket can
/// carry wg + disco; here it just frames STUN).
const DISCO_MAGIC: &[u8; 4] = b"fpd1";

/// Bind a UDP socket and answer disco `Ping`s with `Pong{observed}` forever.
pub async fn serve_stun(addr: SocketAddr) -> std::io::Result<()> {
    let sock = UdpSocket::bind(addr).await?;
    tracing::info!(%addr, "relay-server STUN (UDP) listening");
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        if let Some(body) = buf[..n].strip_prefix(DISCO_MAGIC)
            && let Ok((Disco::Ping { tx_id, .. }, _)) = Disco::decode(body)
        {
            let mut out = DISCO_MAGIC.to_vec();
            out.extend_from_slice(&Disco::Pong { tx_id, observed: from }.encode());
            let _ = sock.send_to(&out, from).await;
        }
    }
}
