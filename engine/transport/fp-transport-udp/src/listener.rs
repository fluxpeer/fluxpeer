use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

/// Channel-based UDP listener that dispatches incoming datagrams by peer address.
///
/// A single shared socket receives all traffic. A background dispatcher task
/// routes datagrams to per-peer mpsc channels. `accept()` picks up the first
/// packet from a previously-unseen peer, registers a channel for it, and
/// returns sender/receiver handles.
#[derive(Debug)]
pub struct Listener {
    pub(crate) timeout: std::time::Duration,
    pub(crate) listener: Arc<tokio::net::UdpSocket>,
    pub(crate) peers: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    pub(crate) new_peer_rx: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl Listener {
    /// Create a new listener and spawn the background dispatcher task.
    pub fn new(socket: tokio::net::UdpSocket, timeout: std::time::Duration) -> Self {
        let socket = Arc::new(socket);
        let peers: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> = Arc::new(Mutex::new(HashMap::new()));
        let (new_peer_tx, new_peer_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(64);

        // Spawn dispatcher task
        let dispatch_socket = socket.clone();
        let dispatch_peers = peers.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, addr) = match dispatch_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("[fp-transport-udp] dispatcher recv error: {e}");
                        break;
                    }
                };
                let data = buf[..n].to_vec();

                let mut map = dispatch_peers.lock().await;
                if let Some(tx) = map.get(&addr) {
                    // Known peer — route to its channel
                    if tx.send(data).await.is_err() {
                        // Peer receiver dropped; remove from map
                        map.remove(&addr);
                    }
                } else {
                    // New peer — notify accept()
                    drop(map);
                    if new_peer_tx.send((data, addr)).await.is_err() {
                        // Listener dropped; stop dispatcher
                        break;
                    }
                }
            }
        });

        Listener {
            timeout,
            listener: socket,
            peers,
            new_peer_rx: Mutex::new(new_peer_rx),
        }
    }
}

#[async_trait::async_trait]
impl fp_transport::Listener for Listener {
    async fn accept(
        &self,
        closer: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    ) -> Result<fp_transport::AcceptResponse, fp_transport::Error> {
        // Wait for a new peer's first packet, with timeout and close support
        let (packet, addr) = tokio::select! {
            res = async {
                let mut rx = self.new_peer_rx.lock().await;
                rx.recv().await
            } => {
                match res {
                    Some(v) => v,
                    None => return Err(fp_transport::Error::ListenerHasBeenClosed),
                }
            },
            _ = closer.recv() => {
                return Err(fp_transport::Error::ListenerHasBeenClosed);
            },
            _ = tokio::time::sleep(self.timeout) => {
                return Err(fp_transport::Error::TimeOut(
                    self.listener.local_addr()
                        .map(|a| a.ip())
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                ));
            },
        };

        let peer_addr = addr.ip();
        tracing::info!("[fp-transport-udp] accept new connection: {}", addr);

        // Create per-peer channel for incoming datagrams
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);

        // Register this peer so the dispatcher routes future packets to the channel
        {
            let mut map = self.peers.lock().await;
            map.insert(addr, tx);
        }

        // Sender: uses the shared socket with send_to to the peer address
        let send_socket = self.listener.clone();
        let sender = Box::new(UdpPeerSender {
            socket: Some(send_socket),
            peer_addr: addr,
        });

        // Receiver: reads from the per-peer mpsc channel
        let receiver = Box::new(crate::ChannelReceiver { rx });

        Ok(fp_transport::AcceptResponse {
            packet,
            sender,
            receiver,
            peer_addr,
        })
    }
}

/// Sender that wraps the shared listener socket and targets a specific peer via `send_to`.
struct UdpPeerSender {
    socket: Option<Arc<tokio::net::UdpSocket>>,
    peer_addr: SocketAddr,
}

#[async_trait::async_trait]
impl fp_transport::TransportSender for UdpPeerSender {
    async fn send(&mut self, pkt: Vec<u8>) -> Result<(), fp_transport::Error> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| fp_transport::Error::UnexpectedResult("sender closed".into()))?;
        socket.send_to(&pkt, self.peer_addr).await.map(|_| ())?;
        Ok(())
    }

    async fn close(&mut self) {
        // Drop the Arc handle; the shared socket stays alive for other peers.
        self.socket.take();
    }
}
