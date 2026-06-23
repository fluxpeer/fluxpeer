//! fp-transport-anytls: TLS + AnyTLS anti-fingerprint + yamux + bond multi-connection transport
//!
//! Architecture:
//! N × (TCP → TLS 1.3 → AnyTLS auth → bond header → yamux)
//! Bonded into one logical (Sender, Receiver) with health-based failover.
//!
//! N is configurable (default 3, range 1-8).

// Vendored anytls-rs modules (auth, padding, TLS utilities)
#[allow(dead_code)]
mod anytls_padding;
#[allow(dead_code)]
mod anytls_util;

// Transport implementation
mod acceptor;
pub mod bond;
mod config;
mod conn;
mod connector;
mod health;
#[allow(dead_code)]
mod pool;
pub mod stream;

pub use acceptor::AnytlsAcceptor;
pub use config::AnytlsConfig;
pub use connector::{AnytlsConnector, build_server_tls, get_config_cloned, set_anytls_config};
pub use health::BondHealthSummary;

/// Test helpers — exposed for integration tests only
#[doc(hidden)]
pub mod __test_helpers {
    pub use crate::anytls_util::{create_client_config, create_server_config, hash_password};
    pub use crate::conn::{
        AcceptedConnection, ManagedConnection, ManagedConnectionWithStream, accept_server_connection, generate_bond_id,
    };

    pub fn create_server_tls() -> Result<std::sync::Arc<rustls::ServerConfig>, fp_transport::Error> {
        create_server_config().map_err(|e| fp_transport::Error::UnexpectedResult(format!("server TLS config: {e}")))
    }

    pub fn create_client_tls() -> Result<std::sync::Arc<rustls::ClientConfig>, fp_transport::Error> {
        create_client_config(true).map_err(|e| fp_transport::Error::UnexpectedResult(format!("client TLS config: {e}")))
    }

    pub async fn connect_managed(
        id: usize,
        addr: std::net::SocketAddr,
        config: &crate::AnytlsConfig,
        tls: &tokio_rustls::TlsConnector,
        bond_id: &[u8; 16],
    ) -> Result<ManagedConnectionWithStream, fp_transport::Error> {
        ManagedConnection::connect(id, addr, config, tls, bond_id).await
    }
}
