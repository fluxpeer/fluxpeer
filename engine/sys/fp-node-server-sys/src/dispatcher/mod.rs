pub mod worker;
pub use worker::Event as Worker;

pub mod operator;

#[derive(Clone)]
pub struct Dispatcher {
    sender: fp_node_core::TokioUnboundedSender<Request>,
    invalids: std::sync::Arc<flume::Receiver<std::net::IpAddr>>,
}

impl Dispatcher {
    pub fn run() -> (Self, impl std::future::Future<Output = ()>) {
        let (sender, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut inner = Inner::default();

        let invalids;
        {
            let (ic_sender, ic_rx) = flume::unbounded();
            invalids = ic_rx.into();

            let mut conhash = fp_conhash::ConsistentHash::new();
            let core_ids_result = core_affinity::get_core_ids();

            if let Some(mut core_ids) = core_ids_result {
                if core_ids.len() > 1 {
                    let _ctrl = core_ids.pop();
                }
                for id in core_ids {
                    let worker_mailbox = worker::run(id.id, sender.clone());
                    conhash.add(&worker_mailbox, 3);
                    use fp_conhash::Node as _;
                    inner.workers.insert(worker_mailbox.name(), worker_mailbox);
                }
            } else {
                let id: usize = 1;
                let worker_mailbox = worker::run(id, sender.clone());
                conhash.add(&worker_mailbox, 3);
                use fp_conhash::Node as _;
                inner.workers.insert(worker_mailbox.name(), worker_mailbox);
            }

            inner.conhash = conhash.into();
            inner.invalid_connections_sender = Some(ic_sender);
        }

        let disp = Self {
            sender: sender.clone(),
            invalids,
        };

        let join_handle = async move {
            while let Some(request) = rx.recv().await {
                request.process(&mut inner, &sender).await;
            }
        };

        (disp, join_handle)
    }
}

pub struct Request {
    event: Event,
    callback: Option<fp_node_core::CallBack>,
}

impl From<Event> for Request {
    fn from(value: Event) -> Self {
        Self {
            event: value,
            callback: None,
        }
    }
}

impl Request {
    async fn process(self, inner: &mut Inner, sender: &fp_node_core::TokioUnboundedSender<Request>) {
        let Request { event, callback } = self;
        let mut _callback = callback.clone();

        if let Event::Worker(_) = &event {
            _callback = None;
        };

        #[cfg(feature = "debug_log")]
        let event_name = event.name();
        #[cfg(feature = "debug_log")]
        tracing::info!("[Dispatcher::Process]recv request: {event_name}");

        let resp = event.process(inner, sender, callback).await;

        #[cfg(feature = "debug_log")]
        if let Err(ref e) = resp {
            tracing::error!("[Dispatcher::Process::{event_name}] process error: {e:?}")
        }

        if let Some(callback) = _callback {
            let _ = callback.send(resp);
        }
    }
}

pub enum Event {
    SetConnector {
        name: String,
        connector: fp_node_core::RawConnector,
    },
    SetCryptor {
        name: String,
        cryptor: fp_node_core::RawCryptor,
    },
    Start(operator::ServerStartReq),
    AssignIface(operator::AssignInterfaceReq),
    IfaceSend {
        packet: Vec<u8>,
    },
    RemoveIface,
    Info,
    Worker(Worker),
    NewListener(operator::AddListenerReq),
    RemoveListener {
        port: u16,
    },
    RetainListener {
        ports: std::collections::HashSet<u16>,
    },
    MarkStaticPorts {
        ports: std::collections::HashSet<u16>,
    },
}

impl Event {
    async fn process(
        self,
        inner: &mut Inner,
        mailbox: &fp_node_core::TokioUnboundedSender<Request>,
        callback: Option<fp_node_core::CallBack>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        match self {
            Event::SetConnector { name, connector } => inner.set_connector(name, connector),
            Event::SetCryptor { name, cryptor } => inner.set_cryptor(name, cryptor).await,
            Event::Start(req) => inner.start(req, mailbox.clone()).await,
            Event::AssignIface(req) => inner.assign_iface(req, mailbox.clone()).await,
            Event::IfaceSend { packet } => inner.iface_send(packet),
            Event::RemoveIface => inner.remove_iface().await,
            Event::Info => inner.info(),
            Event::Worker(mut event) => {
                if let Some(pkey) = event.get_pkey(inner).await
                    && let Some(worker) = inner.dispatch(pkey)
                {
                    worker.process(worker::Request { event, callback })?
                };

                Ok(None)
            }
            Event::NewListener(req) => inner.new_listener(req).await,
            Event::RemoveListener { port } => inner.remove_listener(port),
            Event::RetainListener { ports } => inner.retain_listener(ports),
            Event::MarkStaticPorts { ports } => inner.mark_static_ports(ports),
        }
    }

    #[cfg(feature = "debug_log")]
    fn name(&self) -> String {
        match self {
            Event::SetConnector { .. } => "SetConnector".to_string(),
            Event::SetCryptor { .. } => "SetCryptor".to_string(),
            Event::Start(..) => "Start".to_string(),
            Event::AssignIface(..) => "AssignIface".to_string(),
            Event::IfaceSend { .. } => "IfaceSend".to_string(),
            Event::RemoveIface => "RemoveIface".to_string(),
            Event::Info => "Info".to_string(),
            Event::Worker(..) => "Worker".to_string(),
            Event::NewListener(..) => "NewListener".to_string(),
            Event::RemoveListener { .. } => "RemoveListener".to_string(),
            Event::RetainListener { .. } => "RetainListener".to_string(),
            Event::MarkStaticPorts { .. } => "MarkStaticPorts".to_string(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PeerData {
    #[serde(with = "fp_node_core::key::serde")]
    pub public_key: fp_node_core::x25519::PublicKey,
    pub port: u16,
    pub transport_protocol: String,
    pub crypto_protocol: String,
    pub tx_bytes: u128,
    pub rx_bytes: u128,
    pub latest_active_timestamp: u64,
}

#[derive(serde::Serialize, Clone)]
struct ListenerController {
    #[allow(dead_code)]
    transport_protocol: String,
    crypto_protocol: String,

    #[serde(skip)]
    close_control: fp_node_core::TokioUnboundedSender<()>,
}

impl Drop for ListenerController {
    fn drop(&mut self) {
        tracing::warn!("drop listener");
        let _ = self.close_control.send(());
    }
}

#[derive(Default)]
struct Inner {
    pub iface: Option<fp_node_core::Iface>,
    pub connectors: std::collections::HashMap<String, fp_node_core::RawConnector>,
    pub cryptors: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, fp_node_core::RawCryptor>>>,
    pub key_pair: Option<(fp_node_core::x25519::StaticSecret, fp_node_core::x25519::PublicKey)>,
    /// Keyed by `(port, transport_protocol)` so that TCP-family listeners (demux, tcp,
    /// anytls) and UDP listeners on the **same port number** can coexist. The kernel
    /// treats TCP/443 and UDP/443 as distinct sockets; the old `u16` key caused the second
    /// `open_listener(port=443)` call (for UDP) to be silently dropped as a duplicate.
    pub listener: std::collections::HashMap<(u16, String), ListenerController>,
    /// Ports that were eagerly bound from static config. `retain_listener`
    /// must never drop these even when no peer references them, otherwise the
    /// heartbeat-driven cleanup would tear down the configured ingress.
    pub static_ports: std::collections::HashSet<u16>,
    pub workers: std::collections::HashMap<String, worker::Mailbox>,
    pub conhash: std::sync::Arc<fp_conhash::ConsistentHash<worker::Mailbox>>,
    pub peer_by_ip: fp_node_core::IpTable<PeerData>,
    invalid_connections_sender: Option<flume::Sender<std::net::IpAddr>>,
}

/// The kernel-level layer-4 socket family a transport protocol binds to.
///
/// Listeners only conflict (compete for the same kernel socket) when they share the
/// same `(family, port)` tuple. Reuse/skip logic in [`Inner::new_listener`] is keyed
/// on this, never on the bare port number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum L4Family {
    Tcp,
    Udp,
}

/// Classify a transport-protocol name into its kernel L4 socket family.
///
/// All multiplexed/anti-fingerprint TCP transports (`tcp`, `anytls`, `demux`,
/// `tcp-bond`) share the TCP family — only one may hold the TCP socket on a given
/// port. `udp` is the sole UDP-family transport. Unknown names default to TCP, the
/// safe choice: it errs toward "this might conflict with an existing TCP listener",
/// matching the historical default transport (`tcp`).
fn l4_family(transport_protocol: &str) -> L4Family {
    match transport_protocol {
        "udp" => L4Family::Udp,
        _ => L4Family::Tcp,
    }
}

/// Whether two transport protocols bind the same kernel L4 socket family and therefore
/// cannot both hold a listener on the same port number.
fn same_l4_family(a: &str, b: &str) -> bool {
    l4_family(a) == l4_family(b)
}

impl Inner {
    fn dispatch(&self, pkey: fp_node_core::x25519::PublicKey) -> Option<&worker::Mailbox> {
        self.conhash.get(pkey.as_bytes())
    }

    async fn start(
        &mut self,
        req: operator::ServerStartReq,
        mailbox: fp_node_core::TokioUnboundedSender<Request>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let operator::ServerStartReq {
            set_key_req,
            assign_interface_req,
        } = req;
        let prikey = set_key_req.map(|key| key.prikey);

        self.set_key(prikey)?;
        self.assign_iface(assign_interface_req, mailbox).await?;

        Ok(None)
    }

    fn info(&self) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let peers: std::collections::HashMap<String, serde_json::Value> = self
            .peer_by_ip
            .iter()
            .map(|(pd, ip, _)| {
                let allowed_ips = vec![ip.to_string()];
                (hex::encode(pd.public_key), serde_json::json!({ "allowed_ips": allowed_ips, "tx_bytes": pd.tx_bytes, "rx_bytes": pd.rx_bytes, "latest_active_timestamp": pd.latest_active_timestamp, "port": pd.port, "transport_protocol": pd.transport_protocol, "crypto_protocol": pd.crypto_protocol }))
            })
            .collect();

        // Convert the `(port, protocol)` compound key to a human-readable `"proto:port"` string
        // for JSON serialisation so the heartbeat payload remains a simple string-keyed map.
        let transports: std::collections::HashMap<String, _> = self
            .listener
            .iter()
            .map(|((p, proto), ctrl)| (format!("{proto}:{p}"), ctrl))
            .collect();
        Ok(Some(serde_json::json!({ "transports": transports, "peers": peers })))
    }

    fn set_key(
        &mut self,
        private_key: Option<fp_node_core::x25519::StaticSecret>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let private_key = private_key.unwrap_or(fp_node_core::x25519::StaticSecret::random_from_rng(rand_core::OsRng));
        let public_key = fp_node_core::x25519::PublicKey::from(&private_key);

        self.key_pair = Some((private_key, public_key));
        Ok(None)
    }

    #[allow(clippy::excessive_nesting)]
    async fn new_listener(
        &mut self,
        request: operator::AddListenerReq,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let operator::AddListenerReq {
            transport_protocol,
            crypto_protocol,
            port,
            tls,
        } = request;
        let transport_protocol = transport_protocol.unwrap_or("tcp".to_string());
        let crypto_protocol = crypto_protocol.unwrap_or("noise".to_string());
        // De-duplicate by `(port, L4 family)`, NOT by the exact transport-protocol string.
        //
        // The kernel binds one socket per `(L4 proto, port)` tuple. Every TCP-family
        // transport (`tcp`, `anytls`, `demux`, `tcp-bond`) competes for the *same* TCP
        // socket on a given port, so at most one of them may hold it. UDP is a separate
        // socket and may share the same port number.
        //
        // Two scenarios this guards:
        // 1. demux is eager-bound on TCP/443 as `(443,"demux")`. When a peer arrives over
        // `anytls`/`tcp`, AddPeer calls `new_listener` with `(443,"anytls")`. An exact
        // key match would miss the demux listener and try to `bind(443)` → EADDRINUSE.
        // The demux listener already serves all TCP ingress on 443, so we reuse it.
        // 2. UDP/443 must still bind even when TCP/443 (demux) exists — they are distinct
        // kernel sockets. Keying reuse on the L4 family (not bare port) keeps them
        // independent, avoiding a past regression where a bare-`u16` key silently
        // dropped the UDP listener as a "duplicate" of the TCP one.
        let listener_key = (port, transport_protocol.clone());
        if self
            .listener
            .keys()
            .any(|(p, proto)| *p == port && same_l4_family(proto, &transport_protocol))
        {
            tracing::info!(
                port,
                transport_protocol,
                "port already served by a listener in the same L4 family, reusing (skip bind)"
            );
            return Ok(None);
        }

        let connector = self
            .connectors
            .get(&transport_protocol)
            .ok_or(fp_node_core::Error::NewListenerFailed(
                "Invalid transport protocol".to_string(),
            ))?
            .clone();
        let cryptors = self.cryptors.clone();

        let conhash = self.conhash.clone();
        let (private_key, public_key) = self.key_pair.clone().ok_or(fp_node_core::Error::KeyNotSet)?;
        let listener = connector
            .bind(fp_transport::Config {
                endpoint: std::net::IpAddr::from([0, 0, 0, 0]),
                port,
                timeout: std::time::Duration::from_secs(5),
                tls,
            })
            .await?;
        let ic_sender = self.invalid_connections_sender.clone();

        let on_closed_callback =
            |pkey: fp_node_core::x25519::PublicKey,
             data: String,
             err_message: Option<fp_node_core::DisconnectReason>| {
                tracing::warn!(
                    "[{}]transport closed data: {data}, err_message: {err_message:?}",
                    hex::encode(pkey)
                );
            };
        let on_closed_callback = Box::new(on_closed_callback);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::task::spawn(async move {
            loop {
                let fp_transport::AcceptResponse {
                    packet,
                    mut sender,
                    receiver,
                    peer_addr,
                } = match listener.accept(&mut rx).await {
                    Ok(res) => res,
                    Err(err) => match err {
                        fp_transport::Error::ListenerHasBeenClosed => {
                            tracing::info!(port, "listener closed, exiting accept loop");
                            break;
                        }
                        fp_transport::Error::TimeOut(ip) => {
                            if let Some(ref ic_sender) = ic_sender {
                                let _ = ic_sender.send_async(ip).await;
                            }
                            continue;
                        }
                        other => {
                            tracing::warn!(port, error = ?other, "accept transient error, backing off");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    },
                };

                if let Ok(fp_node_core::Packet::Handshake(fp_node_core::Handshake {
                    cryptor,
                    auth_packet,
                    protocol_version,
                })) = packet.try_into()
                {
                    if !fp_node_core::protocol::client_version_supported(protocol_version) {
                        tracing::warn!(
                            "[handshake] rejecting unsupported client protocol_version {protocol_version} from {peer_addr} (min {})",
                            fp_node_core::protocol::MIN_SUPPORTED_CLIENT_PROTOCOL_VERSION
                        );
                        continue;
                    }

                    if let Some(mut own_crypto) = cryptors.read().await.get(&cryptor).cloned()
                        && let Ok(response) =
                            own_crypto.handle_handshake(private_key.clone(), public_key, auth_packet.as_slice())
                        && let Some(response) = response
                    {
                        if let Err(_e) = sender.send(response).await {
                            tracing::warn!("[fp-transport-tcp] handle handshake_init error: {peer_addr}");
                            continue;
                        }

                        if let Ok(pkey) = own_crypto.get_peer_public()
                            && let Some(mailbox) = conhash.get(pkey.as_bytes())
                            && let Ok(_) = mailbox.process(
                                Worker::SetPeerTransport {
                                    port,
                                    pkey,
                                    cryptor: own_crypto,
                                    sender,
                                    receiver,
                                    on_closed_callback: on_closed_callback.clone(),
                                }
                                .into(),
                            )
                        {
                            tracing::info!("[fp-transport-tcp] {} authenticated", hex::encode(pkey));
                        }

                        continue;
                    }
                }

                if let Some(ref ic_sender) = ic_sender {
                    let _ = ic_sender.send_async(peer_addr).await;
                }
            }
        });
        self.listener.insert(
            listener_key,
            ListenerController {
                transport_protocol,
                crypto_protocol,
                close_control: tx,
            },
        );

        Ok(None)
    }

    fn remove_listener(&mut self, port: u16) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        // Remove all listeners bound to `port` (may be more than one if both TCP-family and
        // UDP listeners share the same port number, e.g. demux:443 and udp:443).
        let removed: Vec<_> = self
            .listener
            .extract_if(|(p, _), _| *p == port)
            .map(|(_, ctrl)| ctrl)
            .collect();
        if removed.is_empty() {
            return Err(fp_node_core::Error::ResourcesNotExist("no such listener".to_string()));
        }
        for ctrl in removed {
            let _ = ctrl.close_control.send(());
        }
        self.workers.values().for_each(|mailbox| {
            if let Err(_e) = mailbox.process(Worker::RemovePeersByPort { port }.into()) {};
        });
        Ok(None)
    }

    fn retain_listener(
        &mut self,
        ports: std::collections::HashSet<u16>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let static_ports = &self.static_ports;
        // Retain listeners whose port is in the active-peer set OR in the static set.
        // The key is now `(port, protocol)` but the caller only supplies port numbers.
        self.listener
            .retain(|(p, _), _| ports.contains(p) || static_ports.contains(p));
        Ok(None)
    }

    fn mark_static_ports(
        &mut self,
        ports: std::collections::HashSet<u16>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        self.static_ports.extend(ports);
        Ok(None)
    }

    fn iface_send(&mut self, packet: Vec<u8>) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let src_addr = fp_crypto::src_address(&packet).ok_or(fp_transport::Error::InvalidPacket)?;
        self.peer_by_ip.find_mut(src_addr).map(|pd| {
            pd.tx_bytes += packet.len() as u128;
            pd.public_key
        });

        if let Some(iface) = &self.iface {
            iface.send(packet);
        }
        Ok(None)
    }

    fn set_connector(
        &mut self,
        name: String,
        connector: fp_node_core::RawConnector,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        self.connectors.insert(name, connector);
        Ok(None)
    }

    async fn set_cryptor(
        &mut self,
        name: String,
        cryptor: fp_node_core::RawCryptor,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        self.cryptors.write().await.insert(name, cryptor);
        Ok(None)
    }

    async fn assign_iface(
        &mut self,
        request: operator::AssignInterfaceReq,
        mailbox: fp_node_core::TokioUnboundedSender<Request>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let operator::AssignInterfaceReq {
            name,
            num,
            ipv4,
            ipv6,
            fd,
            #[cfg(target_os = "windows")]
            path,
        } = request;
        let ipv4 = ipv4.parse().ok();
        let ipv6 = ipv6.parse().ok();

        let (iface_sender, iface_rx) = tokio::sync::mpsc::unbounded_channel();
        let iface_rx = tokio_stream::wrappers::UnboundedReceiverStream::new(iface_rx);
        let mut iface = fp_node_core::Iface::new(
            fp_node_core::iface::IfaceName::new(name.as_str(), num),
            fp_node_core::iface::IfaceAddr::new(ipv4, ipv6),
            #[cfg(target_os = "windows")]
            path,
            fd,
            fp_tun::configuration::Configuration::default(),
            iface_sender,
            None,
        );

        let (sink, stream) = iface
            .assign()
            .map_err(|e| fp_node_core::Error::AssignIfaceFailed(e.to_string()))?;

        let handler = iface_handler(stream, mailbox);
        iface.set_handler(handler);
        self.iface = Some(iface);

        fp_node_core::iface::process(sink, iface_rx).await;
        Ok(None)
    }

    async fn remove_iface(&mut self) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        if let Some(iface) = self.iface.take() {
            #[cfg(target_os = "ios")]
            Box::leak(Box::new(iface));
            #[cfg(not(target_os = "ios"))]
            drop(iface);

            self.listener.clear();
            self.workers.values().for_each(|mailbox| {
                if let Err(_e) = mailbox.process(Worker::ClearPeers.into()) {};
            });
            self.key_pair.take();
        };
        Ok(None)
    }
}

// Server iface handler
pub fn iface_handler(
    mut stream: futures::stream::SplitStream<fp_node_core::iface::IfaceFramed>,
    processor_tx: fp_node_core::TokioUnboundedSender<Request>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        use futures::StreamExt as _;
        loop {
            match stream.next().await {
                Some(Ok(packet)) => {
                    let packet = packet.get_bytes();

                    let _src_addr = match fp_crypto::src_address(packet) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    #[allow(unused)]
                    let dst_addr = match fp_crypto::dst_address(packet) {
                        Some(addr) => addr,
                        None => continue,
                    };

                    #[cfg(feature = "debug_log")]
                    tracing::info!("[FromIFace] dst_addr: {dst_addr}, src_addr: {_src_addr}");

                    let packet = packet.to_vec();

                    if let Err(e) = processor_tx.send(
                        Event::Worker(Worker::TransportSend {
                            dst_addr,
                            packet,
                            pkey: None,
                        })
                        .into(),
                    ) {
                        tracing::error!("[FromIFace]send Worker::TransportSend to Dispatcher::mailbox error: {e:?}")
                    };
                }
                Some(Err(err)) => {
                    tracing::warn!(?err, "iface stream err, exiting iface_handler");
                    break;
                }
                None => {
                    tracing::info!("iface stream EOF, exiting iface_handler");
                    break;
                }
            }
        }
    })
}

pub(crate) fn spawn_reader(
    pkey: fp_node_core::x25519::PublicKey,
    closer: tokio::sync::broadcast::Sender<Option<fp_node_core::DisconnectReason>>,
    mut receiver: Box<dyn fp_transport::TransportReceiver>,
    mut read_close_rx: tokio::sync::broadcast::Receiver<Option<fp_node_core::DisconnectReason>>,
    on_closed_callback: Box<
        dyn Fn(fp_node_core::x25519::PublicKey, String, Option<fp_node_core::DisconnectReason>) + Send,
    >,
    mailbox: fp_node_core::TokioUnboundedSender<worker::Request>,
) {
    tokio::task::spawn(async move {
        tracing::info!("[Dispatcher::SpawnReader]{}: spawn reader.", hex::encode(pkey));
        let err_message;
        let (receiver_tx, mut receiver_rx) = tokio::sync::mpsc::unbounded_channel();

        let receiver_closer = closer.clone();
        let receiver_handler = tokio::task::spawn(async move {
            loop {
                match receiver.recv().await {
                    Ok(packet) => {
                        if receiver_tx.send(packet).is_err() {
                            let _ = receiver_closer.send(Some(fp_node_core::Error::CallbackUnavailable.into()));
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(?err, "receiver_handler recv closed");
                        break;
                    }
                }
            }
        });

        loop {
            #[cfg(feature = "debug_log")]
            tracing::info!("[Dispatcher::SpawnReader]{}: wait for read.", hex::encode(pkey));
            let event = tokio::select! {
                err = read_close_rx.recv() => {
                    err_message = err.unwrap_or(Some(fp_node_core::Error::CallbackUnavailable.into()));
                    tracing::warn!(
                        "[Dispatcher::SpawnReader]{}: read_close_rx received {err_message:?}.",
                        hex::encode(pkey)
                    );
                    break;
                }
                packet = receiver_rx.recv() => {
                    if let Some(packet) = packet
                    && let Ok(packet) = packet.try_into() {
                        match packet {
                            fp_node_core::Packet::Heartbeat(_heartbeat) => continue,
                            fp_node_core::Packet::Handshake(_handshake) => continue,
                            fp_node_core::Packet::ToggleCryptor(_toggle_cryptor) => {
                                tracing::warn!("unhandled packet variant: ToggleCryptor");
                                continue;
                            }
                            fp_node_core::Packet::ToggleTransport(_toggle_transport) => {
                                tracing::warn!("unhandled packet variant: ToggleTransport");
                                continue;
                            }
                            fp_node_core::Packet::Disconnect(reason) => {
                                worker::Event::RemovePeer { pkey, reason: Some(reason) }
                            },
                            fp_node_core::Packet::Data(packet) => {
                                worker::Event::IfaceSend { pkey, packet }
                            },
                        }
                    } else {
                        err_message = Some(fp_node_core::Error::TransportError("Transport has been closed".to_string()).into());
                        tracing::warn!("[Dispatcher::SpawnReader]{}: {err_message:?}.",hex::encode(pkey));
                        break;
                    }
                }
            };

            if mailbox.send(event.into()).is_err() {
                err_message = Some(fp_node_core::Error::CallbackUnavailable.into());
                break;
            }
        }

        receiver_handler.abort();
        let _ = closer.send(err_message.clone());
        tracing::error!("tcp reader closed: {err_message:?}");
        on_closed_callback(pkey, String::new(), err_message);
    });
}

#[cfg(test)]
mod tests {
    use super::{L4Family, l4_family, same_l4_family};

    /// Mirror the de-dup predicate used inside `Inner::new_listener` without needing a
    /// live dispatcher / kernel socket: given the set of `(port, protocol)` keys already
    /// present, decide whether a new `(port, protocol)` request should skip binding.
    fn should_skip_bind(existing: &[(u16, &str)], port: u16, proto: &str) -> bool {
        existing
            .iter()
            .any(|(p, existing_proto)| *p == port && same_l4_family(existing_proto, proto))
    }

    #[test]
    fn tcp_family_protocols_share_one_family() {
        for proto in ["tcp", "anytls", "demux", "tcp-bond"] {
            assert_eq!(l4_family(proto), L4Family::Tcp, "{proto} should be TCP family");
        }
        assert_eq!(l4_family("udp"), L4Family::Udp);
    }

    #[test]
    fn unknown_protocol_defaults_to_tcp_family() {
        // Defaulting to TCP is the conservative choice: the historical default transport
        // is `tcp`, so an unrecognised name is treated as competing for the TCP socket.
        assert_eq!(l4_family("mystery-transport"), L4Family::Tcp);
        assert!(same_l4_family("mystery-transport", "tcp"));
        assert!(!same_l4_family("mystery-transport", "udp"));
    }

    #[test]
    fn same_tcp_family_on_same_port_is_reused() {
        // demux eager-bound on TCP/443; an anytls/tcp peer arriving on 443 must reuse it.
        let existing = [(443u16, "demux")];
        assert!(
            should_skip_bind(&existing, 443, "anytls"),
            "anytls/443 reuses demux/443"
        );
        assert!(should_skip_bind(&existing, 443, "tcp"), "tcp/443 reuses demux/443");
        assert!(
            should_skip_bind(&existing, 443, "tcp-bond"),
            "tcp-bond/443 reuses demux/443"
        );
        // Idempotent: re-requesting the exact same protocol also skips.
        assert!(should_skip_bind(&existing, 443, "demux"));
    }

    #[test]
    fn udp_443_not_mutually_exclusive_with_tcp_443() {
        // The regression guard: a UDP/443 listener must NOT be considered a duplicate of
        // an existing TCP-family (demux) listener on 443. They are distinct kernel sockets.
        let existing = [(443u16, "demux")];
        assert!(
            !should_skip_bind(&existing, 443, "udp"),
            "udp/443 must still bind even though demux holds TCP/443"
        );

        // And the symmetric case: a TCP-family request must not be skipped just because a
        // UDP listener already occupies the same port number.
        let existing_udp = [(443u16, "udp")];
        assert!(
            !should_skip_bind(&existing_udp, 443, "anytls"),
            "anytls/443 (TCP) must bind even though udp/443 exists"
        );
        assert!(!should_skip_bind(&existing_udp, 443, "demux"));
    }

    #[test]
    fn coexisting_tcp_and_udp_on_443_then_third_request() {
        // With both demux/443 (TCP) and udp/443 (UDP) bound, a fresh anytls/443 peer
        // reuses the TCP listener, while a fresh udp/443 reuses the UDP one — neither
        // attempts a (conflicting) bind, and the two families stay independent.
        let existing = [(443u16, "demux"), (443u16, "udp")];
        assert!(should_skip_bind(&existing, 443, "anytls"));
        assert!(should_skip_bind(&existing, 443, "udp"));
    }

    #[test]
    fn different_ports_never_conflict() {
        let existing = [(443u16, "demux")];
        assert!(
            !should_skip_bind(&existing, 8443, "anytls"),
            "different port → must bind"
        );
        assert!(!should_skip_bind(&existing, 5677, "tcp"));
    }
}
