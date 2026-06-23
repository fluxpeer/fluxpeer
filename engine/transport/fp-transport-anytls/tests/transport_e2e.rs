//! E2E transport test: TLS + AnyTLS auth + bond header + yamux over localhost

use fp_transport_anytls::AnytlsConfig;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_raw_conn_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    let port: u16 = {
        use rand::Rng;
        rand::thread_rng().gen_range(40000..=59999)
    };

    let cfg = AnytlsConfig::with_node_id("e2e-raw-test");
    fp_transport_anytls::set_anytls_config(cfg.clone());

    let server_tls = fp_transport_anytls::__test_helpers::create_server_tls().expect("server TLS config");
    let tls_acceptor = std::sync::Arc::new(tokio_rustls::TlsAcceptor::from(server_tls));
    let password_hash = fp_transport_anytls::__test_helpers::hash_password(&cfg.password);

    let tcp_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("bind failed");

    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        let (tcp, _) = tcp_listener.accept().await.expect("tcp accept");
        let mut accepted =
            fp_transport_anytls::__test_helpers::accept_server_connection(tcp, &tls_acceptor, &password_hash)
                .await
                .expect("server setup");

        let stream = accepted.next_inbound().await.expect("no stream").expect("stream err");

        // IMPORTANT: continue driving yamux connection in background so writes get flushed
        tokio::spawn(async move { while let Some(Ok(_)) = accepted.next_inbound().await {} });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let compat = stream.compat();
        let (mut reader, mut writer) = tokio::io::split(compat);

        let mut buf = vec![0u8; 256];
        let n = reader.read(&mut buf).await.expect("read");
        eprintln!("[server] Read {} bytes", n);
        assert_eq!(&buf[..n], b"hello-yamux");

        writer.write_all(&buf[..n]).await.expect("write");
        writer.flush().await.expect("flush");
        eprintln!("[server] Echoed");

        let _ = done_rx.await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_tls = fp_transport_anytls::__test_helpers::create_client_tls().expect("client TLS config");
    let tls_connector = std::sync::Arc::new(tokio_rustls::TlsConnector::from(client_tls));
    let bond_id = fp_transport_anytls::__test_helpers::generate_bond_id();
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let conn = fp_transport_anytls::__test_helpers::connect_managed(0, addr, &cfg, &tls_connector, &bond_id)
        .await
        .expect("connect");

    // `connect_managed` already opens the yamux stream and flushes the SYN, so
    // the stream is carried on the returned struct rather than opened again.
    let stream = conn.stream;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let compat = stream.compat();
    let (mut reader, mut writer) = tokio::io::split(compat);

    writer.write_all(b"hello-yamux").await.expect("write");
    writer.flush().await.expect("flush");
    eprintln!("[client] Sent");

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut buf))
        .await
        .expect("timeout")
        .expect("read");
    assert_eq!(&buf[..n], b"hello-yamux");
    eprintln!("[client] Echo verified: {} bytes", n);

    let _ = done_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server timeout")
        .expect("server panic");

    eprintln!("=== PASSED ===");
}
