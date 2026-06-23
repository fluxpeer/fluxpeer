pub mod model;
pub use model::*;

// Re-export AssignInterfaceReq from core
pub use fp_node_core::iface::{IfaceAddr, IfaceName};

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

    pub async fn start(&self, req: ServerStartReq) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]Start");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::Start(req),
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn stop(&self) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]Stop");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::RemoveIface,
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn invalid_connection(&self) -> Result<std::net::IpAddr, fp_node_core::Error> {
        tracing::info!("[operator] InvalidConnection");
        self.invalids
            .recv_async()
            .await
            .map_err(|_| fp_node_core::Error::CallbackUnavailable)
    }

    pub async fn add_peer(&self, add_peer_req: AddPeerReq) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator] Server AddPeer");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::Worker(super::Worker::AddPeer(add_peer_req)),
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn remove_peer(
        &self,
        pkey: fp_node_core::x25519::PublicKey,
        reason: Option<fp_node_core::DisconnectReason>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]RemovePeer");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::Worker(super::Worker::RemovePeer { pkey, reason }),
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn open_listener(&self, req: AddListenerReq) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]OpenListener");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::NewListener(req),
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn retain_listener(
        &self,
        ports: std::collections::HashSet<u16>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::trace!("[operator]RetainListener");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::RetainListener { ports },
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn close_listener(&self, port: u16) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!("[operator]CloseListener");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::RemoveListener { port },
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    /// Mark a set of ports as "static" so they are protected from
    /// `retain_listener` pruning. Used by the caller after eagerly binding
    /// configured transport listeners at startup.
    pub async fn mark_static_ports(
        &self,
        ports: std::collections::HashSet<u16>,
    ) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        tracing::info!(?ports, "[operator]MarkStaticPorts");
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::MarkStaticPorts { ports },
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }

    pub async fn info(&self) -> Result<Option<serde_json::Value>, fp_node_core::Error> {
        let (callback, mut recv) = tokio::sync::mpsc::unbounded_channel();
        self.sender.send(super::Request {
            event: super::Event::Info,
            callback: Some(callback),
        })?;
        recv.recv().await.ok_or(fp_node_core::Error::CallbackUnavailable)?
    }
}
