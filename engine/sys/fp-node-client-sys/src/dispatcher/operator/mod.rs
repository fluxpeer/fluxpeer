pub mod model;
pub use model::*;

impl super::Dispatcher {
    pub async fn set_connector(
        &self,
        name: String,
        connector: fp_node_core::RawConnector,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]SetConnector");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::SetConnector { name, connector },
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn set_cryptor(
        &self,
        name: String,
        cryptor: fp_node_core::RawCryptor,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]SetCryptor");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::SetCryptor { name, cryptor },
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn start(&self, req: ClientStartReq) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]Start");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::Start(req),
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    /// Phase-1: build transport + run noise handshake, no TUN attach.
    /// Caller must follow up with `attach_iface(...)` once the platform-level
    /// TUN fd is ready (iOS: post `setTunnelNetworkSettings` completion).
    pub async fn handshake_only(&self, req: ClientStartReq) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]HandshakeOnly");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::StartHandshakeOnly(req),
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    /// Phase-2: attach a TUN iface to the existing handshaken session.
    /// Posts `Event::AssignIface` through the existing event channel.
    pub async fn attach_iface(
        &self,
        req: AssignInterfaceReq,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]AttachIface");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::AssignIface(req),
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn stop(&self) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]Stop");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::RemoveIface { reason: None },
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn heartbeat(&self, packet: String) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]Heartbeat");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        let packet = fp_node_core::Packet::Heartbeat(packet.into());
        self.sender.send(super::Request {
            event: super::Event::Heartbeat { packet },
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }
}
