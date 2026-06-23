//! Minimal mobile-gateway server: the server-side counterpart of the mobile
//! `fp-node-client-sys` dispatcher (same protocol). The mesh `fluxpeer node`
//! (magicsock/WireGuard) is NOT protocol-compatible with the mobile client, so
//! this wires `fp-node-server-sys` into a runnable gateway a phone can connect
//! to: UDP listener + Noise, a TUN with the gateway's overlay address, and one
//! allowed peer (the phone).
//!
//! Env:
//! FPGW_PRIKEY server x25519 private key (hex) [required]
//! FPGW_PEER_PUBKEY the phone's wg public key (hex) [required]
//! FPGW_IPV4 gateway overlay address [default 100.72.28.101]
//! FPGW_PEER_ALLOWED phone's allowed-ip CIDR [default 100.72.28.100/32]
//! FPGW_PORT UDP listen port [default 41820]
//!
//! Run as root (creates a TUN): sudo -E./mobilegw

use fp_node_server_sys::operator::{AddListenerReq, AddPeerReq, AssignInterfaceReq, ServerStartReq, SetKeyReq};
use fp_node_server_sys::{Dispatcher, RawConnector, RawCryptor};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();

    let prikey_hex = std::env::var("FPGW_PRIKEY")?;
    let peer_pubkey_hex = std::env::var("FPGW_PEER_PUBKEY")?;
    let iface_ipv4 = env_or("FPGW_IPV4", "100.72.28.101");
    let peer_allowed = env_or("FPGW_PEER_ALLOWED", "100.72.28.100/32");
    let port: u16 = env_or("FPGW_PORT", "41820").parse()?;

    let prikey = fp_node_core::key::gen_prikey_with_str(&prikey_hex)?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&hex::decode(peer_pubkey_hex)?[..32]);
    let peer_pubkey = fp_node_core::x25519::PublicKey::from(pk);

    let (disp, join) = Dispatcher::run();
    tokio::spawn(join);

    disp.set_connector("udp".into(), RawConnector::new::<fp_transport_udp::Connector>()).await?;
    disp.set_cryptor("noise".into(), RawCryptor::new::<fp_crypto_noise::Cryptor>()).await?;

    disp.start(ServerStartReq {
        set_key_req: Some(SetKeyReq { prikey }),
        assign_interface_req: AssignInterfaceReq {
            name: "fpgw".into(),
            num: 0,
            ipv4: iface_ipv4.clone(),
            ipv6: String::new(),
            fd: None,
            #[cfg(target_os = "windows")]
            path: None,
        },
    })
    .await?;

    disp.open_listener(AddListenerReq {
        transport_protocol: Some("udp".into()),
        crypto_protocol: Some("noise".into()),
        port,
        tls: None,
    })
    .await?;

    disp.add_peer(AddPeerReq {
        port,
        transport_protocol: Some("udp".into()),
        crypto_protocol: Some("noise".into()),
        pkey: peer_pubkey,
        allowed_ips: vec![peer_allowed.parse()?],
    })
    .await?;

    // Optional 2nd peer (e.g. an intranet node) so the gateway routes between
    // peers — the phone reaches that node's overlay via this gateway.
    if let (Ok(pk2_hex), Ok(allowed2)) = (std::env::var("FPGW_PEER2_PUBKEY"), std::env::var("FPGW_PEER2_ALLOWED")) {
        let mut pk2 = [0u8; 32];
        pk2.copy_from_slice(&hex::decode(pk2_hex)?[..32]);
        disp.add_peer(AddPeerReq {
            port,
            transport_protocol: Some("udp".into()),
            crypto_protocol: Some("noise".into()),
            pkey: fp_node_core::x25519::PublicKey::from(pk2),
            allowed_ips: vec![allowed2.parse()?],
        })
        .await?;
        println!("mobilegw peer2 added: {allowed2}");
    }

    println!("mobilegw up: udp/{port} iface fpgw={iface_ipv4} peer={peer_allowed}");
    futures::future::pending::<()>().await;
    Ok(())
}
