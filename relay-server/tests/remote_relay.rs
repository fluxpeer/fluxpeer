//! Cross-host smoke test against a REAL running relay-server over the network.
//!
//! Gated on `RELAY_TEST_ADDR` (e.g. `198.51.100.7:3478`) so it is a no-op in
//! environments without a deployed relay. Proves the network layer end-to-end on
//! real sockets between machines: two clients connect through a public relay and
//! a ciphertext datagram is forwarded by pubkey, plus Ping→Pong and PeerGone.

use fluxpeer_relay_server::proto::{Frame, PublicKey};
use fluxpeer_relay_server::server::RELAY_PROTOCOL_VERSION;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn key(b: u8) -> PublicKey {
    [b; 32]
}

async fn write_frame(s: &mut TcpStream, f: Frame) {
    s.write_all(&f.encode()).await.unwrap();
}

async fn read_frame(s: &mut TcpStream) -> Frame {
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr).await.unwrap();
    let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut full = hdr.to_vec();
    full.resize(5 + len, 0);
    s.read_exact(&mut full[5..]).await.unwrap();
    Frame::decode(&full).unwrap().0
}

async fn connect(addr: &str, k: PublicKey) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.expect("connect relay");
    s.set_nodelay(true).unwrap();
    write_frame(
        &mut s,
        Frame::ClientInfo {
            pubkey: k,
            protocol_version: RELAY_PROTOCOL_VERSION,
        },
    )
    .await;
    assert_eq!(
        read_frame(&mut s).await,
        Frame::ServerInfo {
            protocol_version: RELAY_PROTOCOL_VERSION
        }
    );
    s
}

#[tokio::test]
async fn relays_across_the_network() {
    let Some(addr) = std::env::var("RELAY_TEST_ADDR").ok().filter(|s| !s.is_empty()) else {
        eprintln!("SKIP relays_across_the_network: RELAY_TEST_ADDR not set");
        return;
    };
    let (a, b) = (key(0x1A), key(0x2B));

    let mut ca = connect(&addr, a).await;
    let mut cb = connect(&addr, b).await;

    // A → B forwarded by pubkey, payload byte-exact (relay never decrypts).
    let blob: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    write_frame(
        &mut ca,
        Frame::SendPacket {
            dst: b,
            payload: blob.clone(),
        },
    )
    .await;
    assert_eq!(read_frame(&mut cb).await, Frame::RecvPacket { src: a, payload: blob });

    // Ping → Pong.
    write_frame(&mut ca, Frame::Ping { data: [9; 8] }).await;
    assert_eq!(read_frame(&mut ca).await, Frame::Pong { data: [9; 8] });

    // Unknown dst → PeerGone.
    write_frame(
        &mut ca,
        Frame::SendPacket {
            dst: key(0xEE),
            payload: vec![0],
        },
    )
    .await;
    assert_eq!(read_frame(&mut ca).await, Frame::PeerGone { pubkey: key(0xEE) });

    eprintln!("OK: relayed across the network via {addr}");
}
