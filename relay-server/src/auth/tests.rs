// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use tokio::time::{Duration, timeout};

fn pair() -> (ServerAuth, ClientAuth) {
    let server = ServerAuth::new(StaticSecret::from([123; 32]));
    let client = ClientAuth::new(StaticSecret::from([42; 32]), server.public_key()); (server, client)
}
async fn link(server: &ServerAuth, client: &ClientAuth, bond: [u8; 16], index: u32) -> (LinkSessionRef, LinkSessionRef) {
    let (mut a, mut b) = tokio::io::duplex(256);
    let (s, c) = timeout(Duration::from_secs(2), async {
        tokio::join!(server.server(&mut a, bond, index), client.client(&mut b, bond, index))
    }).await.unwrap(); (s.unwrap(), c.unwrap())
}
#[tokio::test]
async fn primary_secondary_and_reconnect_share_identity_and_revocation() {
    let (server, client) = pair(); let bond = [7; 16];
    let (primary, _) = link(&server, &client, bond, 0).await;
    assert_eq!(primary.peer(), client.public_key());
    for index in [1, 2, 10_000] {
        let (secondary, _) = link(&server, &client, bond, index).await;
        assert!(Arc::ptr_eq(&primary, &secondary));
    }
    primary.invalidate();
    let (mut a, _b) = tokio::io::duplex(256);
    assert!(server.server(&mut a, bond, 3).await.is_err());
    assert_eq!(server.rejected_links(), 1);
}
#[tokio::test]
async fn secondary_rejected_immediately_before_and_during_primary_authentication() {
    let (server, client) = pair(); let bond = [8; 16];
    let (mut a, _b) = tokio::io::duplex(256);
    assert!(timeout(Duration::from_millis(100), server.server(&mut a, bond, 1)).await.unwrap().is_err());
    let (mut primary_server, mut primary_client) = tokio::io::duplex(256);
    let primary = server.server(&mut primary_server, bond, 0);
    tokio::pin!(primary);
    primary_client.write_u32(2).await.unwrap(); primary_client.write_all(&client.public_key()).await.unwrap();
    tokio::select! {
        result = &mut primary => panic!("primary must await proof: {:?}", result.err()),
        _ = async { let mut challenge = [0; 32]; primary_client.read_exact(&mut challenge).await.unwrap(); } => {}
    }
    assert!(timeout(Duration::from_millis(100), server.server(&mut a, bond, 2)).await.unwrap().is_err());
    assert_eq!(server.rejected_links(), 2);
}
async fn bad_secondary(server: &ServerAuth, client: &ClientAuth, bond: [u8; 16], index: u32, proof_index: u32, replay: Option<[u8; 32]>) -> [u8; 32] {
    let (mut a, mut b) = tokio::io::duplex(256);
    let session = client.group.lock().as_ref().unwrap().1.clone();
    let (result, proof) = tokio::join!(server.server(&mut a, bond, index), async {
        let mut challenge = [0; 32]; b.read_exact(&mut challenge).await.unwrap();
        let proof = replay.unwrap_or_else(|| session.proof(&challenge, &bond, proof_index).unwrap());
        b.write_all(&proof).await.unwrap(); proof
    });
    assert!(result.is_err()); proof
}
#[tokio::test]
async fn wrong_hmac_index_replayed_nonce_and_old_group_key_are_rejected() {
    let (server, client) = pair(); let bond = [9; 16];
    let (old, _) = link(&server, &client, bond, 0).await;
    bad_secondary(&server, &client, bond, 1, 1, Some([0; 32])).await;
    let proof = bad_secondary(&server, &client, bond, 2, 3, None).await;
    bad_secondary(&server, &client, bond, 3, 3, Some(proof)).await;
    // A new proof of the same WG identity replaces the old Hub session and key.
    let hub = crate::hub::Hub::new(); let (old_tx, _) = hub.connect_authenticated(old.peer(), Some(old.clone()));
    let replacement = ClientAuth::new(StaticSecret::from([42; 32]), server.public_key());
    let (new, _) = link(&server, &replacement, [10; 16], 0).await;
    let (_, _rx) = hub.connect_authenticated(new.peer(), Some(new.clone()));
    assert!(!old.active()); assert!(new.active());
    assert_eq!(hub.route_session(old.peer(), Some(&old_tx), crate::proto::Frame::SendPacket { dst: new.peer(), payload: vec![1] }), crate::hub::Routed::Ignored);
    hub.disconnect_session(&old.peer(), &old_tx); assert!(new.active());
    let (mut a, _b) = tokio::io::duplex(256);
    assert!(server.server(&mut a, bond, 4).await.is_err());
    // Reusing a bond id with fresh primary proof still cannot use the old key.
    let (current, _) = link(&server, &replacement, bond, 0).await;
    bad_secondary(&server, &client, bond, 1, 1, None).await;
    assert!(current.active());
}
#[tokio::test]
async fn low_order_wrong_secret_and_old_protocol_never_establish_identity() {
    let (server, _) = pair();
    for (version, peer) in [(1, [1; 32]), (2, [0; 32])] {
        let (mut a, mut b) = tokio::io::duplex(256);
        b.write_u32(version).await.unwrap(); b.write_all(&peer).await.unwrap();
        assert!(server.server(&mut a, [11; 16], 0).await.is_err());
    }
    let (mut a, mut b) = tokio::io::duplex(256);
    let (result, _) = tokio::join!(server.server(&mut a, [11; 16], 0), async {
        b.write_u32(2).await.unwrap(); b.write_all(&PublicKey::from(&StaticSecret::from([42; 32])).to_bytes()).await.unwrap();
        let mut nonce = [0; 32]; b.read_exact(&mut nonce).await.unwrap(); b.write_all(&[0; 32]).await.unwrap();
    });
    assert!(result.is_err());
}
#[test]
fn persisted_identity_is_random_stable_and_private() {
    let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("relay.key");
    let a = load_identity(&path).unwrap(); let b = load_identity(&path).unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
    let other = load_identity(&dir.path().join("other.key")).unwrap(); assert_ne!(a.to_bytes(), other.to_bytes());
    std::fs::write(&path, [1; 31]).unwrap(); assert!(load_identity(&path).is_err());
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, [1; 32]).unwrap(); std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_identity(&path).is_err());
        let link = dir.path().join("link"); std::os::unix::fs::symlink(&path, &link).unwrap(); assert!(load_identity(&link).is_err());
    }
}

#[tokio::test]
async fn tcp_bond_known_id_injection_rejected_and_valid_reconnect_accepted() {
    bonded_links(false).await;
}
#[tokio::test]
async fn anytls_bond_known_id_injection_rejected_and_valid_reconnect_accepted() {
    bonded_links(true).await;
}
async fn bonded_links(anytls: bool) {
    use fp_transport::{Config, link::{read_header, write_header}};
    // Reserve an ephemeral loopback port; this is an in-process transport fixture.
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reservation.local_addr().unwrap(); drop(reservation);
    let config = || Config { endpoint: addr.ip(), port: addr.port(), timeout: Duration::from_secs(2), tls: None };
    let (server, client) = pair(); let server = Arc::new(server); let client = Arc::new(client);
    if anytls { fp_transport_anytls::set_anytls_config(fp_transport_anytls::AnytlsConfig::with_node_id("test-edge")); }
    let delayed: fp_transport::link::Authenticator = Arc::new(DelayedPrimary(server.clone()));
    let listener = if anytls {
        fp_transport_anytls::AnytlsConnector::bind_authenticated(config(), Some(delayed.clone())).await.unwrap()
    } else { fp_transport_tcp_bond::TcpBondConnector::bind_authenticated(config(), Some(delayed.clone())).await.unwrap() };
    let (_keep, mut closer) = tokio::sync::mpsc::unbounded_channel();
    let (mut tx, _rx) = timeout(Duration::from_secs(5), async {
        if anytls { fp_transport_anytls::AnytlsConnector::connect_authenticated(config(), Some(client.clone())).await }
        else { fp_transport_tcp_bond::TcpBondConnector::connect_authenticated(config(), Some(client.clone())).await }
    }).await.unwrap().unwrap();
    tx.send(b"first".to_vec()).await.unwrap();
    let mut accepted = timeout(Duration::from_secs(5), listener.accept(&mut closer)).await.unwrap().unwrap();
    assert_eq!(accepted.packet, b"first");
    let bond = client.group.lock().as_ref().unwrap().0;
    if anytls {
        let cfg = fp_transport_anytls::get_config_cloned();
        let tls = tokio_rustls::TlsConnector::from(fp_transport_anytls::__test_helpers::create_client_tls().unwrap());
        assert!(fp_transport_anytls::__test_helpers::ManagedConnection::connect_authenticated(9, addr, &cfg, &tls, &bond, Some(Arc::new(BadProof))).await.is_err());
    } else {
        let mut attack = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_header(&mut attack, &bond, 3, 9, true).await.unwrap();
        assert!(BadProof.client(&mut attack, bond, 9).await.is_err());
    }
    assert_eq!(server.rejected_links(), 1);
    // The existing session still works after an attacker knows the entire header.
    tx.send(b"still-authorized".to_vec()).await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), accepted.receiver.recv()).await.unwrap().unwrap(), b"still-authorized");
    // A reconnect must deliver bytes through the existing receiver, not merely
    // obtain an authentication acknowledgement before transport membership.
    let (_connection, stream): (Box<dyn Send>, _) = if anytls {
        let cfg = fp_transport_anytls::get_config_cloned();
        let tls = tokio_rustls::TlsConnector::from(fp_transport_anytls::__test_helpers::create_client_tls().unwrap());
        let conn = fp_transport_anytls::__test_helpers::ManagedConnection::connect_authenticated(10, addr, &cfg, &tls, &bond, Some(client.clone())).await.unwrap();
        (Box::new(conn.conn), conn.stream)
    } else {
        let conn = fp_transport_tcp_bond::__test_helpers::ManagedConnection::connect_authenticated(10, addr, &fp_transport_tcp_bond::TcpBondConfig::default(), &bond, Some(client.clone())).await.unwrap();
        let stream = conn.open_stream().await.unwrap(); (Box::new(conn), stream)
    };
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let mut stream = stream.compat();
    stream.write_u32(9).await.unwrap(); stream.write_all(b"reconnect").await.unwrap(); stream.flush().await.unwrap();
    assert_eq!(timeout(Duration::from_secs(2), accepted.receiver.recv()).await.unwrap().unwrap(), b"reconnect");
    assert_eq!(server.rejected_links(), 1);
    accepted.sender.close().await; tx.close().await;
    // Old protocol headers reject explicitly (no implicit downgrade).
    let (mut a, mut b) = tokio::io::duplex(32); b.write_u8(1).await.unwrap();
    assert!(read_header(&mut a, true).await.unwrap_err().to_string().contains("version 2"));
}

struct BadProof;
#[async_trait::async_trait]
impl LinkAuthenticator for BadProof {
    async fn server(&self, _: &mut dyn LinkIo, _: [u8; 16], _: u32) -> io::Result<LinkSessionRef> { Err(denied("test client")) }
    async fn client(&self, io: &mut dyn LinkIo, _: [u8; 16], _: u32) -> io::Result<LinkSessionRef> {
        let mut challenge = [0; 32]; io.read_exact(&mut challenge).await?;
        io.write_all(&[0; 32]).await?; io.flush().await?;
        let mut reply = [0; 32];
        match timeout(Duration::from_secs(2), io.read_exact(&mut reply)).await {
            Ok(Err(_)) => Err(denied("bad proof rejected")),
            result => panic!("unauthorized link was not rejected: {result:?}"),
        }
    }
}

#[tokio::test]
async fn direct_tcp_bond_without_hook_still_roundtrips() {
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reservation.local_addr().unwrap(); drop(reservation);
    let cfg = || fp_transport::Config { endpoint: addr.ip(), port: addr.port(), timeout: Duration::from_secs(2), tls: None };
    let listener = fp_transport_tcp_bond::TcpBondConnector::bind_authenticated(cfg(), None).await.unwrap();
    let (mut tx, _rx) = fp_transport_tcp_bond::TcpBondConnector::connect_authenticated(cfg(), None).await.unwrap();
    assert!(tx.link_session().is_none());
    tx.send(b"direct-wg-frame".to_vec()).await.unwrap();
    let (_keep, mut closer) = tokio::sync::mpsc::unbounded_channel();
    let response = timeout(Duration::from_secs(2), listener.accept(&mut closer)).await.unwrap().unwrap();
    assert!(response.sender.link_session().is_none()); assert_eq!(response.packet, b"direct-wg-frame");
}

// Make the proof-confirmation / transport-publication race deterministic.
struct DelayedPrimary(Arc<ServerAuth>);
#[async_trait::async_trait]
impl LinkAuthenticator for DelayedPrimary {
    async fn client(&self, _: &mut dyn LinkIo, _: [u8; 16], _: u32) -> io::Result<LinkSessionRef> { Err(denied("test server")) }
    async fn server(&self, io: &mut dyn LinkIo, bond: [u8; 16], index: u32) -> io::Result<LinkSessionRef> {
        let session = self.0.server(io, bond, index).await?;
        if index == 0 { tokio::time::sleep(Duration::from_millis(100)).await; }
        Ok(session)
    }
}

#[test]
fn identity_path_precedence_and_system_default() {
    use std::path::PathBuf;
    assert_eq!(resolve_identity_path(None, None, None), PathBuf::from("/var/lib/fluxpeer/relay.key"));
    assert_eq!(resolve_identity_path(None, None, Some("state".into())), PathBuf::from("state/relay.key"));
    assert_eq!(resolve_identity_path(None, Some("env.key".into()), Some("state".into())), PathBuf::from("env.key"));
    assert_eq!(resolve_identity_path(Some("cli.key".into()), Some("env.key".into()), Some("state".into())), PathBuf::from("cli.key"));
}

#[tokio::test]
async fn closure_before_confirmation_and_bad_mac_are_auth_failures() {
    for bad_mac in [false, true] {
        let (_server, client) = pair();
        let (mut local, mut remote) = tokio::io::duplex(256);
        let fixture = async move {
            let mut hello = [0; 36]; remote.read_exact(&mut hello).await.unwrap();
            remote.write_all(&[19; 32]).await.unwrap();
            let mut proof = [0; 32]; remote.read_exact(&mut proof).await.unwrap();
            if bad_mac { remote.write_all(&[0; 32]).await.unwrap(); }
            // Wrong pin makes the real relay close here, without confirmation.
        };
        let (result, ()) = tokio::join!(client.client(&mut local, [0; 16], 0), fixture);
        let error = result.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.get_ref().unwrap().is::<AuthenticationFailure>());
        let cause = &error.get_ref().unwrap().downcast_ref::<AuthenticationFailure>().unwrap().0;
        assert_eq!(cause.kind(), if bad_mac { io::ErrorKind::PermissionDenied } else { io::ErrorKind::UnexpectedEof });
    }
}
