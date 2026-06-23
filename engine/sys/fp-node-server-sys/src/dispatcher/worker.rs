pub(super) fn run(id: usize, ctrl_mailbox: fp_node_core::TokioUnboundedSender<super::Request>) -> Mailbox {
    let name = format!("worker-{id}");
    let (sender, rx) = tokio::sync::mpsc::unbounded_channel();
    let mut rx = tokio_stream::wrappers::UnboundedReceiverStream::new(rx);

    let mailbox = sender.clone();
    tokio::task::spawn(async move {
        let mut inner = Inner::new(ctrl_mailbox);
        let mut buf = vec![0u8; fp_node_core::MAX_PACKET_SIZE];

        use tokio_stream::StreamExt as _;
        while let Some(request) = rx.next().await {
            let Request { event, callback } = request;
            let resp = match event {
                Event::UpdatePeer => {
                    tracing::warn!("unhandled worker event: UpdatePeer");
                    Ok(None)
                }
                Event::ClearPeers => inner.clear_peer(),
                Event::SetPeerTransport {
                    port,
                    pkey,
                    cryptor,
                    sender,
                    receiver,
                    on_closed_callback,
                } => {
                    inner
                        .set_transport(
                            port,
                            pkey,
                            cryptor,
                            sender,
                            receiver,
                            on_closed_callback,
                            mailbox.clone(),
                        )
                        .await
                }
                Event::TransportSend {
                    pkey,
                    dst_addr: _,
                    packet,
                } => {
                    if let Some(pkey) = pkey {
                        inner.transport_send(pkey, packet, &mut buf).await
                    } else {
                        Err(fp_node_core::Error::PeerNotExist)
                    }
                }
                Event::AddPeer(req) => inner.add_peer(req),
                Event::RemovePeer { pkey, reason } => inner.remove_peer(pkey, reason).await,
                Event::RemovePeersByPort { port } => inner.remove_peer_by_port(port),
                Event::IfaceSend { pkey, packet } => inner.iface_send(pkey, packet, &mut buf),
            };

            if let Some(callback) = callback {
                let _res = callback.send(resp);
            };
        }
    });
    Mailbox { name, sender }
}

pub struct Request {
    pub(crate) event: Event,
    pub(crate) callback: Option<fp_node_core::CallBack>,
}

impl From<Event> for Request {
    fn from(value: Event) -> Self {
        Self {
            event: value,
            callback: None,
        }
    }
}

pub enum Event {
    AddPeer(super::operator::AddPeerReq),
    UpdatePeer,
    ClearPeers,
    RemovePeer {
        pkey: fp_node_core::x25519::PublicKey,
        reason: Option<fp_node_core::DisconnectReason>,
    },
    RemovePeersByPort {
        port: u16,
    },
    SetPeerTransport {
        port: u16,
        pkey: fp_node_core::x25519::PublicKey,
        cryptor: fp_node_core::RawCryptor,
        sender: fp_node_core::TransportSender,
        receiver: fp_node_core::TransportReceiver,
        on_closed_callback:
            Box<dyn Fn(fp_node_core::x25519::PublicKey, String, Option<fp_node_core::DisconnectReason>) + Send>,
    },
    TransportSend {
        pkey: Option<fp_node_core::x25519::PublicKey>,
        dst_addr: std::net::IpAddr,
        packet: Vec<u8>,
    },
    IfaceSend {
        pkey: fp_node_core::x25519::PublicKey,
        packet: Vec<u8>,
    },
}

impl Event {
    pub(super) async fn get_pkey(&mut self, dispatcher: &mut super::Inner) -> Option<fp_node_core::x25519::PublicKey> {
        match self {
            Event::AddPeer(super::operator::AddPeerReq {
                transport_protocol,
                crypto_protocol,
                port,
                pkey,
                allowed_ips,
            }) => {
                if let Err(e) = dispatcher
                    .new_listener(super::operator::AddListenerReq {
                        transport_protocol: transport_protocol.clone(),
                        crypto_protocol: crypto_protocol.clone(),
                        port: *port,
                        tls: None,
                    })
                    .await
                {
                    tracing::error!(
                        port = *port,
                        transport = transport_protocol.as_deref().unwrap_or("tcp"),
                        crypto = crypto_protocol.as_deref().unwrap_or("noise"),
                        "new_listener failed during AddPeer: {}",
                        e
                    );
                }
                let latest_active_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let pd = super::PeerData {
                    public_key: *pkey,
                    port: *port,
                    transport_protocol: transport_protocol.clone().unwrap_or("tcp".to_string()),
                    crypto_protocol: crypto_protocol.clone().unwrap_or("noise".to_string()),
                    tx_bytes: 0,
                    rx_bytes: 0,
                    latest_active_timestamp,
                };
                for fp_node_core::AllowedIP { addr, cidr } in allowed_ips {
                    dispatcher.peer_by_ip.insert(*addr, *cidr as _, pd.clone());
                }
                Some(*pkey)
            }
            Event::RemovePeer { pkey, .. } => {
                dispatcher.peer_by_ip.remove(&|pd| pd.public_key == *pkey);
                Some(*pkey)
            }
            Event::SetPeerTransport { pkey, .. } => Some(*pkey),
            Event::TransportSend { dst_addr, pkey, packet } => {
                let _ = std::mem::replace(
                    pkey,
                    dispatcher.peer_by_ip.find_mut(*dst_addr).map(|pd| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        pd.latest_active_timestamp = now;
                        pd.rx_bytes += packet.len() as u128;
                        pd.public_key
                    }),
                );
                *pkey
            }
            _ => None,
        }
    }

    #[cfg(feature = "debug_log")]
    fn name(&self) -> String {
        match self {
            Event::IfaceSend { .. } => "IfaceSend".to_string(),
            Event::AddPeer { .. } => "AddPeer".to_string(),
            Event::UpdatePeer { .. } => "UpdatePeer".to_string(),
            Event::ClearPeers { .. } => "ClearPeers".to_string(),
            Event::RemovePeer { .. } => "RemovePeer".to_string(),
            Event::RemovePeersByPort { .. } => "RemovePeersByPort".to_string(),
            Event::SetPeerTransport { .. } => "SetPeerTransport".to_string(),
            Event::TransportSend { .. } => "TransportSend".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct Mailbox {
    name: String,
    sender: fp_node_core::TokioUnboundedSender<Request>,
}

impl Mailbox {
    pub fn process(&self, request: Request) -> Result<(), fp_node_core::Error> {
        self.sender
            .send(request)
            .map_err(|_| fp_node_core::Error::WorkerMailboxError(self.name.clone()))
    }
}

impl fp_conhash::Node for Mailbox {
    fn name(&self) -> String {
        self.name.to_string()
    }
}

struct Inner {
    ctrl_mailbox: fp_node_core::TokioUnboundedSender<super::Request>,
    peers: std::collections::HashMap<fp_node_core::x25519::PublicKey, crate::Peer>,
    peer_by_port: std::collections::HashMap<u16, Vec<fp_node_core::x25519::PublicKey>>,
    crypto_by_pkey: std::collections::HashMap<fp_node_core::x25519::PublicKey, fp_node_core::RawCryptor>,
}

impl Inner {
    fn new(ctrl_mailbox: fp_node_core::TokioUnboundedSender<super::Request>) -> Self {
        Inner {
            ctrl_mailbox,
            peers: Default::default(),
            peer_by_port: Default::default(),
            crypto_by_pkey: Default::default(),
        }
    }

    async fn set_transport(
        &mut self,
        port: u16,
        pkey: fp_node_core::x25519::PublicKey,
        cryptor: fp_node_core::RawCryptor,
        sender: fp_node_core::TransportSender,
        receiver: fp_node_core::TransportReceiver,
        on_closed_callback: Box<
            dyn Fn(fp_node_core::x25519::PublicKey, String, Option<fp_node_core::DisconnectReason>) + Send,
        >,
        mailbox: fp_node_core::TokioUnboundedSender<Request>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let (closer, close_rx) = tokio::sync::broadcast::channel(1);
        let read_close_rx = closer.subscribe();
        let mut peer_inner = fp_node_core::PeerInner {
            sender,
            closer: closer.clone(),
            close_rx,
        };

        self.crypto_by_pkey.insert(pkey, cryptor);
        if let Some(peer) = self.peers.get_mut(&pkey) {
            super::spawn_reader(pkey, closer, receiver, read_close_rx, on_closed_callback, mailbox);
            if let Some(old) = peer.inner.replace(peer_inner) {
                drop(old);
            };
            self.peer_by_port.entry(port).or_default().push(pkey);
        } else {
            self.crypto_by_pkey.remove(&pkey);
            peer_inner.sender.close().await;
            let _ = peer_inner.closer.send(None);
        }

        Ok(None)
    }

    async fn transport_send(
        &mut self,
        pkey: fp_node_core::x25519::PublicKey,
        packet: Vec<u8>,
        buf: &mut [u8],
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let peer = self.peers.get_mut(&pkey).ok_or(fp_node_core::Error::PeerNotExist)?;
        let peer_inner = peer.inner.as_mut().ok_or(fp_node_core::Error::PeerTransportNotExist)?;

        let cryptor = self
            .crypto_by_pkey
            .get_mut(&pkey)
            .ok_or(fp_node_core::Error::PeerCryptorNotExist)?;

        peer_inner
            .send(cryptor, fp_node_core::Packet::Data(packet), buf)
            .await
            .map(|_| None)
    }

    fn add_peer(&mut self, req: super::operator::AddPeerReq) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        self.peers
            .entry(req.pkey)
            .or_insert(crate::Peer::new(req.allowed_ips.as_slice()));

        Ok(None)
    }

    async fn remove_peer(
        &mut self,
        pkey: fp_node_core::x25519::PublicKey,
        reason: Option<fp_node_core::DisconnectReason>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        if let Some(mut inner) = self
            .peers
            .remove(&pkey)
            .ok_or(fp_node_core::Error::ResourcesNotExist("peer not found".to_string()))?
            .inner
            .take()
        {
            inner.close(reason).await;
        };

        // Clean up peer_by_port entry for this peer
        self.peer_by_port.values_mut().for_each(|pkeys| {
            pkeys.retain(|k| *k != pkey);
        });
        self.crypto_by_pkey.remove(&pkey);

        Ok(None)
    }

    fn remove_peer_by_port(&mut self, port: u16) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        if let Some(peers) = self.peer_by_port.remove(&port) {
            peers.into_iter().for_each(|pkey| {
                self.peers.remove(&pkey);
                self.crypto_by_pkey.remove(&pkey);
            });
        };

        Ok(None)
    }

    fn clear_peer(&mut self) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        self.peers.clear();
        self.peer_by_port.clear();
        self.crypto_by_pkey.clear();

        Ok(None)
    }

    fn iface_send(
        &mut self,
        pkey: fp_node_core::x25519::PublicKey,
        packet: Vec<u8>,
        buf: &mut [u8],
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let cryptor = self
            .crypto_by_pkey
            .get_mut(&pkey)
            .ok_or(fp_node_core::Error::PeerCryptorNotExist)?;
        let packet = cryptor.on_recv(packet.as_slice(), buf)?.to_vec();
        // An empty result is a keepalive — authenticated, but nothing to deliver.
        if !packet.is_empty() {
            self.ctrl_mailbox.send(super::Event::IfaceSend { packet }.into())?;
        }

        Ok(None)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn mem_replace() {
        #[derive(Debug, PartialEq, Eq)]
        enum A {
            B(u64),
        }

        let mut a = A::B(1);
        match &mut a {
            A::B(old) => std::mem::replace(old, 3),
        };

        assert_eq!(a, A::B(3))
    }
}
