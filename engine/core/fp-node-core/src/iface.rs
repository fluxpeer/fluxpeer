pub type IfaceFramed = tokio_util::codec::Framed<fp_tun::AsyncDevice, fp_tun::TunPacketCodec>;

pub enum Event {
    WriteToIface(Vec<u8>),
    Close,
}

pub async fn process(
    mut writer: futures::stream::SplitSink<IfaceFramed, fp_tun::TunPacket>,
    mut iface_rx: tokio_stream::wrappers::UnboundedReceiverStream<Event>,
) {
    tokio::spawn(async move {
        use futures::SinkExt as _;
        use tokio_stream::StreamExt as _;

        while let Some(event) = iface_rx.next().await {
            let _ = match event {
                Event::WriteToIface(packet) => writer.send(fp_tun::TunPacket::new(packet)).await,
                Event::Close => break,
            };
            #[cfg(feature = "debug_log")]
            tracing::info!("[Iface]writed.");
        }
    });
}

#[derive(Debug, Default)]
pub struct IfaceAddr {
    pub ipv4: Option<std::net::Ipv4Addr>,
    #[allow(unused)]
    pub ipv6: Option<std::net::Ipv6Addr>,
}

impl IfaceAddr {
    pub fn new(ipv4: Option<std::net::Ipv4Addr>, ipv6: Option<std::net::Ipv6Addr>) -> Self {
        Self { ipv4, ipv6 }
    }
    pub fn get_ipv4(&self) -> Result<std::net::Ipv4Addr, crate::Error> {
        self.ipv4.ok_or(crate::Error::IfaceNotSet)
    }
}

#[derive(Debug, Default)]
pub struct IfaceName {
    name: String,
    num: u16,
}

impl IfaceName {
    pub fn new(name: &str, num: u16) -> Self {
        Self {
            name: name.to_string(),
            num,
        }
    }

    pub fn gen_iface_name(&self) -> String {
        #[cfg(target_os = "macos")]
        {
            format!("{}{}", self.name, self.num + 1)
        }

        #[cfg(not(target_os = "macos"))]
        {
            // If name already ends with a digit (e.g. "tun0" from legacy config),
            // use it as-is to avoid generating "tun00".
            if self.name.ends_with(|c: char| c.is_ascii_digit()) {
                self.name.clone()
            } else {
                format!("{}{}", self.name, self.num)
            }
        }
    }
}

pub struct Iface {
    pub name: IfaceName,
    pub addr: IfaceAddr,
    #[cfg(target_os = "windows")]
    pub path: Option<String>,
    pub fd: Option<i32>,
    pub conf: fp_tun::configuration::Configuration,

    pub sender: tokio::sync::mpsc::UnboundedSender<Event>,
    handler: Option<tokio::task::JoinHandle<()>>,
}

impl Iface {
    pub fn new(
        name: IfaceName,
        addr: IfaceAddr,
        #[cfg(target_os = "windows")] path: Option<String>,
        fd: Option<i32>,
        conf: fp_tun::configuration::Configuration,
        sender: tokio::sync::mpsc::UnboundedSender<Event>,
        handler: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self {
            name,
            addr,
            #[cfg(target_os = "windows")]
            path,
            fd,
            conf,
            sender,
            handler,
        }
    }

    pub fn send(&self, packet: Vec<u8>) {
        if let Err(_e) = self.sender.send(Event::WriteToIface(packet)) {
            // TODO: process err
        };
    }

    pub fn assign(
        &mut self,
    ) -> Result<
        (
            futures::stream::SplitSink<IfaceFramed, fp_tun::TunPacket>,
            futures::stream::SplitStream<IfaceFramed>,
        ),
        crate::Error,
    > {
        let ipv4 = self.addr.get_ipv4()?;

        let config = self.conf.address(ipv4).destination(ipv4);

        if let Some(fd) = self.fd {
            // Pre-created fd from helper — don't set name, Device::new() will read
            // the actual interface name from the socket via getsockopt
            config.raw_fd(fd);
            tracing::info!("[assign_interface] using pre-created fd: {fd}");
        } else {
            let name = self.name.gen_iface_name();
            config.name(name.as_str());
            tracing::info!("[assign_interface] creating new interface: {name:?}");
        }

        #[cfg(target_os = "windows")]
        if let Some(path) = self.path.as_ref() {
            config.path(path);
        }

        // Don't set up() when using pre-created fd — helper already configured the interface
        #[cfg(not(any(target_os = "ios")))]
        if self.fd.is_none() {
            config.up();
        }

        use futures::StreamExt as _;
        let dev = fp_tun::create_as_async(config)?;
        let stream = dev.into_framed();
        let (sink, stream) = stream.split();
        Ok((sink, stream))
    }

    pub fn set_handler(&mut self, handler: tokio::task::JoinHandle<()>) {
        self.handler = Some(handler);
    }
}

impl Drop for Iface {
    fn drop(&mut self) {
        let _ = self.sender.send(Event::Close);
        self.conf.down();
        if let Some(handler) = self.handler.as_ref() {
            handler.abort()
        };
    }
}
