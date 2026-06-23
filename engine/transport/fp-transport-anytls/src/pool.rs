//! Legacy single-connection pool (kept for reference).
//! The bond module now provides multi-connection resilience.

use crate::config::AnytlsConfig;
use crate::conn::ManagedConnection;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ConnectionPool {
    connections: RwLock<Vec<Arc<RwLock<ManagedConnection>>>>,
    config: AnytlsConfig,
    server_addr: SocketAddr,
    tls_connector: Arc<tokio_rustls::TlsConnector>,
    next_id: std::sync::atomic::AtomicUsize,
}

impl ConnectionPool {
    pub fn new(config: AnytlsConfig, server_addr: SocketAddr, tls_connector: Arc<tokio_rustls::TlsConnector>) -> Self {
        Self {
            connections: RwLock::new(Vec::new()),
            config,
            server_addr,
            tls_connector,
            next_id: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub async fn init(&self) -> Result<(), fp_transport::Error> {
        let target = self.config.effective_bond_connections();
        let bond_id = crate::conn::generate_bond_id();
        for _ in 0..target {
            self.add_connection(&bond_id).await?;
        }
        tracing::info!(count = target, "Connection pool initialized");
        Ok(())
    }

    async fn add_connection(&self, bond_id: &[u8; 16]) -> Result<(), fp_transport::Error> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cws = ManagedConnection::connect(id, self.server_addr, &self.config, &self.tls_connector, bond_id).await?;
        self.connections.write().await.push(Arc::new(RwLock::new(cws.conn)));
        Ok(())
    }

    pub async fn open_stream(&self) -> Result<(yamux::Stream, usize), fp_transport::Error> {
        let conns = self.connections.read().await;
        if conns.is_empty() {
            return Err(fp_transport::Error::UnexpectedResult("no connections".into()));
        }

        // Pick first available
        let conn = conns[0].clone();
        drop(conns);
        let c = conn.read().await;
        let stream = c.open_stream().await?;
        let id = c.id;
        Ok((stream, id))
    }

    pub async fn health_check_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.health_check_interval);
        loop {
            interval.tick().await;
            let conns = self.connections.read().await;
            for conn_arc in conns.iter() {
                let conn = conn_arc.read().await;
                let _ = conn.ping(self.config.health_check_timeout).await;
            }
        }
    }
}
