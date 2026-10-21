// SPDX-License-Identifier: BSD-3-Clause
use super::*;

fn packet(source: &str) -> Vec<u8> {
    match source.parse::<std::net::IpAddr>().unwrap() {
        std::net::IpAddr::V4(ip) => {
            let mut packet = vec![0; 20]; packet[0] = 0x45;
            packet[2..4].copy_from_slice(&20u16.to_be_bytes());
            packet[12..16].copy_from_slice(&ip.octets());
            packet[16..20].copy_from_slice(&[198, 51, 100, 10]);
            packet
        }
        std::net::IpAddr::V6(ip) => {
            let mut packet = vec![0; 40]; packet[0] = 0x60;
            packet[8..24].copy_from_slice(&ip.octets());
            packet
        }
    }
}

#[tokio::test]
async fn decrypted_sources_are_checked_on_udp_tcp_and_relay_before_tun_delivery() {
    let own = StaticSecret::from([21; 32]); let remote = StaticSecret::from([22; 32]);
    let own_pub = PublicKey::from(&own); let remote_pub = PublicKey::from(&remote);
    let prefixes = vec!["100.72.16.2/32".into(), "fd00::2/128".into(), "192.168.8.0/24".into()];
    let stat = PeerStat::new(prefixes.clone());
    let mut peer = Peer::fresh(*remote_pub.as_bytes(), vec![], false, stat.clone(), &own);
    let init = peer.raw.init_handshake(own.clone(), remote_pub).unwrap();
    let index = le_u32(&init, 4).unwrap();
    let mut sender = fp_crypto::RawCryptor::new::<fp_crypto_noise::Cryptor>();
    let response = sender.handle_handshake(remote, remote_pub, &init).unwrap().unwrap();
    peer.raw.handle_handshake_response(&response).unwrap();
    let mut wire = [0; 2048]; let mut plain = [0; 2048];
    sender.on_recv(peer.raw.on_send(&[], &mut wire).unwrap(), &mut plain).unwrap();
    let (tun_out, mut tun_in) = mpsc::channel(16);
    let registry = status::registry(); registry.write().insert(*remote_pub.as_bytes(), stat.clone());
    let mut state = WorkerState {
        peers: vec![peer], index_map: IndexTable::new(HashMap::from([(index, *remote_pub.as_bytes())]), Arc::default(), 0),
        udp: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), relay_out: None,
        own_priv: own, own_pub, force_relay: false, tun_out, status: registry,
        allowed: Arc::new(arc_swap::ArcSwap::from_pointee(RouteTable::default().with_peer(*remote_pub.as_bytes(), 0, &prefixes))),
    };
    let mut drops = 0;
    for via in ["udp", "tcp", "relay"] {
        for (source, accepted) in [
            ("100.72.16.2", true), ("100.72.16.3", false), // another member
            ("192.168.8.9", true), ("192.168.9.9", false), // another LAN
            ("fd00::2", true), ("fd00::3", false),
            ("203.0.113.9", false), // client -> exit must use its own source
        ] {
            let packet = packet(source);
            let encrypted = sender.on_send(&packet, &mut wire).unwrap();
            match via {
                "udp" => state.on_udp_in("127.0.0.1:12345".parse().unwrap(), encrypted, &mut plain).await,
                "tcp" => state.on_tcp_in(*remote_pub.as_bytes(), encrypted, &mut plain).await,
                _ => state.on_relay_in(*remote_pub.as_bytes(), encrypted, &mut plain).await,
            }
            if accepted { assert_eq!(tun_in.try_recv().unwrap(), packet); }
            else { drops += 1; assert!(tun_in.try_recv().is_err()); }
            assert_eq!(status::snapshot(&state.status)[0].rx_source_drops, drops);
        }
    }
    // The same session becomes the selected exit: default prefixes permit
    // public return sources. Removing selection revokes that permission live.
    for (allowed, accepted) in [
        (vec!["0.0.0.0/0".into(), "::/0".into()], true),
        (prefixes, false),
        (vec![], false),
    ] {
        state.allowed.store(Arc::new(state.allowed.load().with_peer(*remote_pub.as_bytes(), 0, &allowed)));
        for source in ["203.0.113.9", "2001:db8::9"] {
            let packet = packet(source);
            let encrypted = sender.on_send(&packet, &mut wire).unwrap();
            state.on_relay_in(*remote_pub.as_bytes(), encrypted, &mut plain).await;
            if accepted { assert_eq!(tun_in.try_recv().unwrap(), packet); }
            else { drops += 1; assert!(tun_in.try_recv().is_err()); }
        }
    }
    // Keepalives authenticate and refresh liveness without source-drop counts.
    let encrypted = sender.on_send(&[], &mut wire).unwrap();
    state.on_relay_in(*remote_pub.as_bytes(), encrypted, &mut plain).await;
    assert!(tun_in.try_recv().is_err());
    assert_eq!(stat.rx_source_drops.load(Ordering::Relaxed), drops);
    assert!(state.peers[0].last_recv.is_some());
    assert!(stat.rx_bytes.load(Ordering::Relaxed) > 0);
}

#[test]
fn source_authorization_fails_closed_for_short_unknown_wrong_peer_and_wrong_family_packets() {
    let peer = [1; 32];
    let table = RouteTable::default().with_peer(peer, 0, &["0.0.0.0/0".into(), "bad".into()]);
    for invalid in [vec![], vec![0x45; 19], vec![0x60; 39], vec![0x70; 40], packet("fd00::2")] {
        assert!(!table.accepts_source(&peer, &invalid));
    }
    assert!(table.accepts_source(&peer, &packet("100.72.16.2")));
    assert!(!table.accepts_source(&[2; 32], &packet("100.72.16.2")));
    let table = table.with_peer(peer, 0, &["invalid".into(), "100.72.16.2/33".into()]);
    assert!(!table.accepts_source(&peer, &packet("100.72.16.2")));
}

#[test]
fn conflicting_prefix_receive_owner_matches_egress_and_promotes_the_next_owner() {
    for order in [[9u8, 4], [4, 9]] {
        let mut table = RouteTable::default();
        for id in order { table = table.with_peer([id; 32], 0, &["10.0.0.0/8".into(), "fd00::/16".into()]); }
        for source in ["10.1.2.3", "fd00::2"] {
            let packet = packet(source);
            assert!(table.accepts_source(&[4; 32], &packet));
            assert!(!table.accepts_source(&[9; 32], &packet));
        }
        let mut egress = packet("10.1.2.3"); egress[16..20].copy_from_slice(&[10, 1, 2, 3]);
        assert_eq!(route_tun(&egress, &table), Some(([4; 32], 0)));
        table = table.with_peer([4; 32], 0, &[]);
        assert!(table.accepts_source(&[9; 32], &packet("10.1.2.3")));
        assert!(!table.accepts_source(&[4; 32], &packet("10.1.2.3")));
        assert_eq!(route_tun(&egress, &table), Some(([9; 32], 0)));
    }
}

/// Exercise the actual decrypt -> authorize -> TUN path with a reconciler-owned
/// route snapshot. Shared only with the reconcile regression below cfg(test).
pub(crate) async fn assert_public_delivery(allowed: Arc<arc_swap::ArcSwap<RouteTable>>, remote_seed: u8, accepted: bool) {
    assert_source_delivery(allowed, remote_seed, "203.0.113.9", accepted).await;
}

pub(crate) async fn assert_source_delivery(allowed: Arc<arc_swap::ArcSwap<RouteTable>>, remote_seed: u8, source: &str, accepted: bool) {
    let own = StaticSecret::from([21; 32]); let remote = StaticSecret::from([remote_seed; 32]);
    let own_pub = PublicKey::from(&own); let remote_pub = PublicKey::from(&remote);
    let stat = PeerStat::new(vec![]);
    let mut peer = Peer::fresh(*remote_pub.as_bytes(), vec![], false, stat.clone(), &own);
    let init = peer.raw.init_handshake(own.clone(), remote_pub).unwrap();
    let mut sender = fp_crypto::RawCryptor::new::<fp_crypto_noise::Cryptor>();
    let response = sender.handle_handshake(remote, remote_pub, &init).unwrap().unwrap();
    peer.raw.handle_handshake_response(&response).unwrap();
    let mut wire = [0; 2048]; let mut plain = [0; 2048];
    sender.on_recv(peer.raw.on_send(&[], &mut wire).unwrap(), &mut plain).unwrap();
    let (tun_out, mut tun_in) = mpsc::channel(4);
    let mut state = WorkerState {
        peers: vec![peer], index_map: IndexTable::new(HashMap::new(), Arc::default(), 0),
        udp: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()), relay_out: None,
        own_priv: own, own_pub, force_relay: false, tun_out, status: status::registry(), allowed,
    };
    let packet = packet(source);
    state.on_relay_in(*remote_pub.as_bytes(), sender.on_send(&packet, &mut wire).unwrap(), &mut plain).await;
    if accepted { assert_eq!(tun_in.try_recv().unwrap(), packet); }
    else { assert!(tun_in.try_recv().is_err()); }
    assert_eq!(stat.rx_source_drops.load(Ordering::Relaxed), u64::from(!accepted));
}

#[tokio::test]
async fn source_lpm_rejects_nested_subnet_spoofing_but_preserves_legitimate_traffic() {
    let broad = PublicKey::from(&StaticSecret::from([22; 32])).to_bytes();
    let narrow = PublicKey::from(&StaticSecret::from([23; 32])).to_bytes();
    for order in [[broad, narrow], [narrow, broad]] {
        let mut table = RouteTable::default();
        for key in order {
            let prefixes = if key == broad { ["10.0.0.0/8".into(), "fd00::/32".into()] }
                else { ["10.1.0.0/16".into(), "fd00:0:1::/48".into()] };
            table = table.with_peer(key, 0, &prefixes);
        }
        let allowed = Arc::new(arc_swap::ArcSwap::from_pointee(table));
        for (source, owner_seed) in [("10.1.2.3", 23), ("10.2.2.3", 22), ("fd00:0:1::5", 23), ("fd00:0:2::5", 22)] {
            for seed in [22, 23] { assert_source_delivery(allowed.clone(), seed, source, seed == owner_seed).await; }
        }
    }
}
