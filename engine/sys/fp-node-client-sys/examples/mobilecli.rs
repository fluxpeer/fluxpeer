//! Headless mesh client (desktop counterpart of the mobile FFI client) — connects
//! to a `mobilegw` gateway and brings up a real TUN, so an intranet server can be
//! a node on the mesh the phone reaches via the gateway.
//!
//! Env:
//! FPCLI_PRIKEY this node's x25519 private key (hex) [required]
//! FPCLI_NODE_PUBKEY gateway x25519 public key (hex) [required]
//! FPCLI_NODE_ADDR gateway ip [required]
//! FPCLI_IPV4 this node's overlay address [required]
//! FPCLI_NODE_PORT gateway udp port [default 41820]
//!
//! Run as root (creates a TUN). After it's up, add a mesh route:
//! ip route add 100.72.28.0/24 dev <tun> (tun name printed at start)

use std::os::raw::c_char;

use fp_node_client_sys::operator::ClientStartReq;
use fp_node_client_sys::{Dispatcher, RawConnector, RawCryptor};

extern "C" fn noop(_data: *const c_char, _err: *const c_char) {}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("missing env {k}"))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();

    let req = ClientStartReq {
        client_prikey: env("FPCLI_PRIKEY"),
        node_pubkey: env("FPCLI_NODE_PUBKEY"),
        node_addr: env("FPCLI_NODE_ADDR"),
        node_port: std::env::var("FPCLI_NODE_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(41820),
        tls: None,
        transport_protocol: "udp".into(),
        crypto_protocol: "noise".into(),
        iface_ipv4: env("FPCLI_IPV4"),
        iface_ipv6: None,
        timeout: None,
        #[cfg(target_os = "windows")]
        path: None,
        fd: None,
        on_connected_callback: None,
        on_closed_callback: noop,
    };
    let (addr, port, ipv4) = (req.node_addr.clone(), req.node_port, req.iface_ipv4.clone());

    let (disp, join) = Dispatcher::run();
    tokio::spawn(join);
    disp.set_connector("udp".into(), RawConnector::new::<fp_transport_udp::Connector>()).await?;
    disp.set_cryptor("noise".into(), RawCryptor::new::<fp_crypto_noise::Cryptor>()).await?;
    disp.start(req).await?;

    println!("mobilecli connected: overlay {ipv4} via {addr}:{port}");
    futures::future::pending::<()>().await;
    Ok(())
}
