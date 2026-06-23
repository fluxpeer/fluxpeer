pub mod operator;

fn configure_optional_ipv6(iface_name: &str, ipv6: Option<&std::net::Ipv6Addr>) -> Result<(), String> {
    let Some(ipv6) = ipv6 else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("ip")
            .args(["-6", "addr", "add", &format!("{ipv6}/128"), "dev", iface_name])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("failed to add IPv6 address on {iface_name}"));
        }
        for cidr in ["::/1", "8000::/1"] {
            let status = std::process::Command::new("ip")
                .args(["-6", "route", "replace", cidr, "dev", iface_name])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("failed to add IPv6 route {cidr} on {iface_name}"));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("ifconfig")
            .args([iface_name, "inet6", &format!("{ipv6}/128"), "alias"])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("failed to add IPv6 address on {iface_name}"));
        }
        for cidr in ["::/1", "8000::/1"] {
            let status = std::process::Command::new("route")
                .args(["-n", "add", "-inet6", cidr, "-interface", iface_name])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("failed to add IPv6 route {cidr} on {iface_name}"));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        let status = std::process::Command::new("netsh")
            .args(["interface", "ipv6", "add", "address", iface_name, &ipv6.to_string()])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("failed to add IPv6 address on {iface_name}"));
        }
        for cidr in ["::/1", "8000::/1"] {
            let status = std::process::Command::new("netsh")
                .args(["interface", "ipv6", "add", "route", cidr, iface_name])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("failed to add IPv6 route {cidr} on {iface_name}"));
            }
        }
    }

    #[cfg(target_os = "android")]
    {
        let status = std::process::Command::new("ip")
            .args(["-6", "addr", "add", &format!("{ipv6}/128"), "dev", iface_name])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("failed to add IPv6 address on {iface_name}"));
        }
        for cidr in ["::/1", "8000::/1"] {
            let status = std::process::Command::new("ip")
                .args(["-6", "route", "replace", cidr, "dev", iface_name])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("failed to add IPv6 route {cidr} on {iface_name}"));
            }
        }
    }

    #[cfg(target_os = "ios")]
    {
        let _ = (iface_name, ipv6);
    }

    Ok(())
}

#[derive(Clone)]
pub struct Dispatcher {
    sender: fp_node_core::TokioUnboundedSender<Request>,
}

impl Dispatcher {
    pub fn run() -> (Self, impl std::future::Future<Output = ()>) {
        let (sender, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut inner = Inner::default();

        let mut buf = vec![0u8; fp_node_core::MAX_PACKET_SIZE];

        let disp = Self { sender: sender.clone() };

        let join_handle = async move {
            while let Some(request) = rx.recv().await {
                request.process(&mut inner, &sender, &mut buf).await;
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
    async fn process(self, inner: &mut Inner, sender: &fp_node_core::TokioUnboundedSender<Request>, buf: &mut [u8]) {
        let Request { event, callback } = self;
        let _callback = callback.clone();

        #[cfg(feature = "debug_log")]
        let event_name = event.name();
        #[cfg(feature = "debug_log")]
        tracing::info!("[Dispatcher::Process]recv request: {event_name}");

        let resp = event.process(inner, sender, buf, callback).await;

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
    Start(operator::ClientStartReq),
    /// Build transport + run noise handshake only; do NOT assign TUN iface.
    /// Used by iOS PacketTunnelProvider phase-1 to validate connectivity
    /// before activating `setTunnelNetworkSettings`.
    StartHandshakeOnly(operator::ClientStartReq),
    AssignIface(operator::AssignInterfaceReq),
    IfaceSend {
        packet: Vec<u8>,
    },
    RemoveIface {
        reason: Option<fp_node_core::DisconnectReason>,
    },
    SendEndpoint {
        packet: fp_node_core::Packet,
    },
    Heartbeat {
        packet: fp_node_core::Packet,
    },
}

impl Event {
    async fn process(
        self,
        inner: &mut Inner,
        mailbox: &fp_node_core::TokioUnboundedSender<Request>,
        buf: &mut [u8],
        _callback: Option<fp_node_core::CallBack>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        match self {
            Event::SetConnector { name, connector } => inner.set_connector(name, connector),
            Event::SetCryptor { name, cryptor } => inner.set_cryptor(name, cryptor),
            Event::Start(req) => inner.start(req, mailbox.clone()).await,
            Event::StartHandshakeOnly(req) => inner.start_handshake_only(req, mailbox.clone()).await,
            Event::AssignIface(req) => inner.assign_iface(req, mailbox.clone()).await,
            Event::IfaceSend { packet } => inner.iface_send(packet, buf),
            Event::RemoveIface { reason } => inner.remove_iface(reason).await,
            Event::SendEndpoint { packet } => inner.send_endpoint(packet, buf).await,
            Event::Heartbeat { packet } => inner.send_endpoint(packet, buf).await,
        }
    }

    #[cfg(feature = "debug_log")]
    fn name(&self) -> String {
        match self {
            Event::SetConnector { .. } => "SetConnector".to_string(),
            Event::SetCryptor { .. } => "SetCryptor".to_string(),
            Event::Start(..) => "Start".to_string(),
            Event::StartHandshakeOnly(..) => "StartHandshakeOnly".to_string(),
            Event::AssignIface(..) => "AssignIface".to_string(),
            Event::IfaceSend { .. } => "IfaceSend".to_string(),
            Event::RemoveIface { .. } => "RemoveIface".to_string(),
            Event::SendEndpoint { .. } => "SendEndpoint".to_string(),
            Event::Heartbeat { .. } => "Heartbeat".to_string(),
        }
    }
}

#[derive(Default)]
struct Inner {
    pub iface: Option<fp_node_core::Iface>,
    pub connectors: std::collections::HashMap<String, fp_node_core::RawConnector>,
    pub cryptors: std::collections::HashMap<String, fp_node_core::RawCryptor>,
    pub peer: Option<fp_node_core::PeerInner>,
    pub cryptor: Option<fp_node_core::RawCryptor>,
}

impl Inner {
    fn set_connector(
        &mut self,
        name: String,
        connector: fp_node_core::RawConnector,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        self.connectors.insert(name, connector);
        Ok(None)
    }

    fn set_cryptor(
        &mut self,
        name: String,
        cryptor: fp_node_core::RawCryptor,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        self.cryptors.insert(name, cryptor);
        Ok(None)
    }

    async fn start(
        &mut self,
        req: operator::ClientStartReq,
        mailbox: fp_node_core::TokioUnboundedSender<Request>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let (transport_config, assign_interface_req) = req.split()?;
        self.new_transport(transport_config, mailbox.clone()).await?;

        tracing::info!("waiting for assign iface");
        self.assign_iface(assign_interface_req, mailbox).await?;
        tracing::info!("assign iface ok");

        Ok(None)
    }

    /// Phase-1 of two-step connect: complete transport handshake without
    /// assigning the TUN iface. Caller invokes `attach_iface` separately
    /// once `setTunnelNetworkSettings` (iOS) / VpnService.Builder.establish()
    /// (Android) has produced the fd.
    async fn start_handshake_only(
        &mut self,
        req: operator::ClientStartReq,
        mailbox: fp_node_core::TokioUnboundedSender<Request>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let (transport_config, _assign_interface_req) = req.split()?;
        self.new_transport(transport_config, mailbox).await?;
        tracing::info!("handshake_only complete; awaiting attach_iface");
        Ok(None)
    }

    async fn new_transport(
        &mut self,
        config: operator::TransportConfig,
        mailbox: fp_node_core::TokioUnboundedSender<Request>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let connector = self
            .connectors
            .get(&config.transport_protocol)
            .ok_or(fp_node_core::Error::NewListenerFailed(
                "Invalid transport protocol".to_string(),
            ))?
            .clone();
        let cryptor = self
            .cryptors
            .get(&config.crypto_protocol)
            .ok_or(fp_node_core::Error::NewListenerFailed(
                "Invalid crypto protocol".to_string(),
            ))?
            .clone();
        let cryptor = self.cryptor.insert(cryptor);

        let close_mailbox = mailbox.clone();
        let transport_config_rf = config.gen_rf_transport_config();
        let on_connected_callback = config.on_connected_callback;
        let on_closed_fn = config.on_closed_callback;
        let on_closed_callback =
            move |pkey: fp_node_core::x25519::PublicKey,
                  data: String,
                  reason: Option<fp_node_core::DisconnectReason>| {
                tracing::warn!(
                    "[{}]transport closed data: {data}, err_message: {reason:?}",
                    hex::encode(pkey)
                );
                let data = std::ffi::CString::new(data).unwrap_or_default().into_raw();
                let err_message = reason
                    .clone()
                    .map(|r| serde_json::to_vec(&r).unwrap_or_default())
                    .unwrap_or_default();
                let err_message = std::ffi::CString::new(err_message).unwrap_or_default().into_raw();
                let _ = close_mailbox.send(Event::RemoveIface { reason }.into());
                (on_closed_fn)(data, err_message)
            };
        let on_closed_callback = Box::new(on_closed_callback);

        let auth_packet = cryptor.init_handshake(config.own_prikey, config.node_pubkey)?;
        let auth_packet: fp_node_core::Packet = fp_node_core::Handshake {
            cryptor: config.crypto_protocol,
            auth_packet,
            protocol_version: fp_node_core::protocol::CLIENT_PROTOCOL_VERSION,
        }
        .into();
        let (closer, close_rx) = tokio::sync::broadcast::channel(1);
        let read_close_rx = closer.subscribe();

        let (mut sender, mut receiver) = connector.connect(transport_config_rf).await?;
        let auth_bytes: Vec<u8> = auth_packet.try_into()?;

        const HANDSHAKE_MAX_RETRIES: u32 = 3;
        const HANDSHAKE_TIMEOUT_SECS: u64 = 3;

        let mut handshake_result = None;
        for attempt in 0..HANDSHAKE_MAX_RETRIES {
            if attempt > 0 {
                tracing::warn!("[Handshake] retry attempt {attempt}/{HANDSHAKE_MAX_RETRIES}");
            }
            sender.send(auth_bytes.clone()).await?;

            match tokio::time::timeout(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), receiver.recv()).await {
                Ok(Ok(response)) => {
                    handshake_result = Some(response);
                    break;
                }
                Ok(Err(e)) => {
                    sender.close().await;
                    receiver.close().await;
                    return Err(fp_node_core::Error::TransportError(format!(
                        "handshake transport error: {e}"
                    )));
                }
                Err(_) => {
                    tracing::warn!(
                        "[Handshake] timeout waiting for response (attempt {}/{})",
                        attempt + 1,
                        HANDSHAKE_MAX_RETRIES,
                    );
                }
            }
        }

        let handshake = match handshake_result {
            Some(handshake) => handshake,
            None => {
                sender.close().await;
                receiver.close().await;
                return Err(fp_node_core::Error::TransportError(format!(
                    "handshake failed after {HANDSHAKE_MAX_RETRIES} attempts"
                )));
            }
        };
        cryptor.handle_handshake_response(handshake.as_slice())?;

        tracing::info!(">>> handshake completed <<<");

        // Notify any phase-aware caller (e.g. iOS PacketTunnelProvider) that the
        // noise handshake finished successfully so it can flip TUN settings on.
        if let Some(cb) = on_connected_callback {
            let data = std::ffi::CString::new("connected").unwrap_or_default().into_raw();
            let err_message = std::ffi::CString::new("").unwrap_or_default().into_raw();
            (cb)(data, err_message);
        }

        let peer_inner = fp_node_core::PeerInner {
            sender,
            closer: closer.clone(),
            close_rx,
        };

        spawn_reader(
            cryptor.get_peer_public()?,
            closer,
            receiver,
            read_close_rx,
            on_closed_callback,
            mailbox,
        );
        tracing::info!("Transport has been builded");

        if let Some(mut old) = self.peer.replace(peer_inner) {
            tracing::warn!("remove old transport");
            old.close(None).await;
        };

        tracing::info!("new transport ok");
        Ok(None)
    }

    async fn send_endpoint(
        &mut self,
        packet: fp_node_core::Packet,
        buf: &mut [u8],
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let sender = self.peer.as_mut().ok_or_else(|| {
            let err = fp_node_core::Error::PeerTransportNotExist;
            tracing::error!("[Dispatcher::SendEndpoint]{err:?}");
            err
        })?;
        let cryptor = self.cryptor.as_mut().ok_or_else(|| {
            let err = fp_node_core::Error::PeerCryptorNotExist;
            tracing::error!("[Dispatcher::SendEndpoint]{err:?}");
            err
        })?;
        #[cfg(feature = "debug_log")]
        tracing::info!("[Dispatcher::SendEndpoint]waiting for send.");
        let res = sender.send(cryptor, packet, buf).await.map(|_| None);
        match res {
            Err(fp_node_core::Error::CryptoFailed(fp_crypto::Error::NonceExhausted)) => {
                tracing::error!("[Dispatcher::SendEndpoint]NonceExhausted — triggering session teardown.");
                Err(fp_node_core::Error::CryptoFailed(fp_crypto::Error::NonceExhausted))
            }
            Err(fp_node_core::Error::CryptoFailed(e)) => {
                tracing::warn!("[Dispatcher::SendEndpoint] CryptoFailed: {e:?}, packet dropped");
                Ok(None)
            }
            _ => res,
        }
    }

    fn iface_send(
        &mut self,
        packet: Vec<u8>,
        buf: &mut [u8],
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let cryptor = self.cryptor.as_mut().ok_or(fp_node_core::Error::PeerCryptorNotExist)?;
        let packet = cryptor.on_recv(packet.as_slice(), buf)?.to_vec();
        // An empty result is a keepalive — authenticated, but nothing to deliver.
        if !packet.is_empty()
            && let Some(iface) = &self.iface
        {
            iface.send(packet);
        }
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
        let iface_name = fp_node_core::iface::IfaceName::new(name.as_str(), num).gen_iface_name();
        let ipv4 = ipv4.parse().ok();
        let ipv6 = ipv6.as_deref().and_then(|value| value.parse().ok());

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

        if let Err(e) = configure_optional_ipv6(&iface_name, ipv6.as_ref()) {
            tracing::warn!("[assign_iface] IPv6 setup failed on {iface_name}, falling back to IPv4-only: {e}");
        }

        let handler = iface_handler(stream, mailbox);
        iface.set_handler(handler);
        self.iface = Some(iface);

        fp_node_core::iface::process(sink, iface_rx).await;
        Ok(None)
    }

    async fn remove_iface(
        &mut self,
        reason: Option<fp_node_core::DisconnectReason>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        // Tear down iface if present (preserves iOS Box::leak path).
        if let Some(iface) = self.iface.take() {
            #[cfg(target_os = "ios")]
            Box::leak(Box::new(iface));
            #[cfg(not(target_os = "ios"))]
            drop(iface);
        }

        // Always close peer/transport, even when iface was never assigned
        // (handshake_only phase leaves iface=None but peer present).
        if let Some(mut peer) = self.peer.take() {
            peer.close(reason).await;
        }

        // Drop the cryptor so a subsequent start() rebuilds noise state cleanly.
        self.cryptor = None;

        Ok(None)
    }
}

// Client iface handler
fn iface_handler(
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
                        Event::SendEndpoint {
                            packet: fp_node_core::Packet::Data(packet),
                        }
                        .into(),
                    ) {
                        tracing::error!("[FromIFace]send SendEndpoint to Dispatcher::mailbox error: {e:?}")
                    };
                }
                Some(Err(e)) => {
                    tracing::error!("[FromIFace] TUN read error: {e:?}");
                    break;
                }
                None => {
                    tracing::warn!("[FromIFace] TUN stream closed");
                    break;
                }
            }
        }
        // After loop exits, notify dispatcher to clean up
        let _ = processor_tx.send(Event::RemoveIface { reason: None }.into());
    })
}

fn spawn_reader(
    pkey: fp_node_core::x25519::PublicKey,
    closer: tokio::sync::broadcast::Sender<Option<fp_node_core::DisconnectReason>>,
    mut receiver: Box<dyn fp_transport::TransportReceiver>,
    mut read_close_rx: tokio::sync::broadcast::Receiver<Option<fp_node_core::DisconnectReason>>,
    on_closed_callback: Box<
        dyn Fn(fp_node_core::x25519::PublicKey, String, Option<fp_node_core::DisconnectReason>) + Send,
    >,
    mailbox: fp_node_core::TokioUnboundedSender<Request>,
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
                    Err(e) => {
                        tracing::warn!("[receiver_handler] transport recv error: {e}");
                        let _ = receiver_closer.send(Some(
                            fp_node_core::Error::TransportError(format!("transport recv failed: {e}")).into(),
                        ));
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
                    match packet {
                        Some(raw_packet) => {
                            match raw_packet.try_into() {
                                Ok(packet) => {
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
                                            Event::RemoveIface { reason: Some(reason) }
                                        },
                                        fp_node_core::Packet::Data(packet) => {
                                            Event::IfaceSend { packet }
                                        },
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("[SpawnReader]{}: packet parse error (skipping): {e:?}", hex::encode(pkey));
                                    continue;
                                }
                            }
                        }
                        None => {
                            err_message = Some(fp_node_core::Error::TransportError("Transport channel closed".to_string()).into());
                            tracing::warn!("[SpawnReader]{}: receiver channel closed", hex::encode(pkey));
                            break;
                        }
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
