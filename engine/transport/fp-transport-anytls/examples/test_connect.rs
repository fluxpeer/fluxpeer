use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info,yamux=info,fp_transport_anytls=debug")
        .init();

    let node_id = "node-001";
    let addr: SocketAddr = "94.131.3.101:443".parse().unwrap();

    let cfg = fp_transport_anytls::AnytlsConfig::with_node_id(node_id);
    println!(
        "bond_connections={}, server_name={}, insecure={}",
        cfg.bond_connections, cfg.server_name, cfg.insecure_skip_verify
    );

    let tls_config = fp_transport_anytls::__test_helpers::create_client_tls().unwrap();
    let tls_connector = std::sync::Arc::new(tokio_rustls::TlsConnector::from(tls_config));

    println!("Testing full bond ({} connections) to {addr} ...", cfg.bond_connections);
    match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        fp_transport_anytls::bond::build_client_bond(&cfg, addr, &tls_connector),
    )
    .await
    {
        Ok(Ok(group)) => {
            let n = group.alive_count().await;
            println!(
                "SUCCESS: BondGroup established with {n}/{} alive connections",
                cfg.bond_connections
            );
        }
        Ok(Err(e)) => {
            println!("BOND FAILED: {e}");
        }
        Err(_) => {
            println!("TIMEOUT after 20s");
        }
    }
}
