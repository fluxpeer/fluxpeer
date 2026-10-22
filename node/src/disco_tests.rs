// SPDX-License-Identifier: BSD-3-Clause
use super::*;
#[tokio::test]
async fn captured_ping_and_unsolicited_pong_cannot_redirect_but_challenged_source_can() {
    let own = StaticSecret::from([71; 32]); let remote = StaticSecret::from([72; 32]);
    let pubkey = PublicKey::from(&remote).to_bytes(); let own_pub = PublicKey::from(&own);
    let old: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap(); let from = source.local_addr().unwrap();
    let attacker: SocketAddr = "127.0.0.1:1235".parse().unwrap();
    let mut peer = Peer::fresh(pubkey, vec![old], false, PeerStat::new(vec![]), &own);
    peer.disco_validated = true; let routes = peer.disco_routes.clone(); let key = peer.disco_key;
    let (tun_out, _) = mpsc::channel(1);
    let mut state = WorkerState { peers: vec![peer], disco_routes: routes.clone(), index_map: IndexTable::new(HashMap::new(), Arc::default(), 0),
        udp: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), relay_out: None, own_priv: own, own_pub, force_relay: false,
        tun_out, status: Arc::default(), allowed: Arc::default() };
    let id = crate::util::disco_tx_id();
    let ping = auth_disco_dgram(&key, &Disco::Ping { tx_id: id, sender: pubkey });
    state.on_disco(from, &ping).await;
    assert_eq!(state.peers[0].direct_addr, Some(old));
    let mut wire = [0; 256];
    let (n, _) = source.recv_from(&mut wire).await.unwrap();
    assert!(matches!(Disco::decode(&wire[4..n]).unwrap().0, Disco::Pong { .. }));
    let (n, _) = source.recv_from(&mut wire).await.unwrap();
    let Disco::Ping { tx_id: challenge, .. } = Disco::decode(&wire[4..n]).unwrap().0 else { panic!("expected challenge") };
    // Captured Ping at a different source is dropped without adding a new probe.
    let pending = routes.lock().len(); state.on_disco(attacker, &ping).await;
    assert_eq!(routes.lock().len(), pending); assert_eq!(state.peers[0].direct_addr, Some(old));
    let unsolicited = auth_disco_dgram(&key, &Disco::Pong { tx_id: id, observed: from });
    state.on_disco(from, &unsolicited).await; assert_eq!(state.peers[0].direct_addr, Some(old));
    let pong = auth_disco_dgram(&key, &Disco::Pong { tx_id: challenge, observed: from });
    // The dispatcher routes a pending Pong from a previously unknown NAT address.
    assert_eq!(route_udp(&pong, from, &HashMap::from([(pubkey, 0)]), &routes, &Arc::default(), &state.own_priv, &own_pub), Some(0));
    state.on_disco(attacker, &pong).await; assert_eq!(state.peers[0].direct_addr, Some(old));
    let mut bad_mac = pong.clone(); *bad_mac.last_mut().unwrap() ^= 1;
    state.on_disco(from, &bad_mac).await; assert_eq!(state.peers[0].direct_addr, Some(old));
    state.on_disco(from, &pong).await; assert_eq!(state.peers[0].direct_addr, Some(from)); assert!(state.peers[0].disco_validated);
    state.peers[0].direct_addr = Some(old); state.on_disco(from, &pong).await;
    assert_eq!(state.peers[0].direct_addr, Some(old)); assert_eq!(crate::disco::owner(&routes, &challenge), None);
}
