//! fp-transport-tcp-bond: TCP multi-connection bonding WITHOUT TLS
//!
//! Protocol stack: App -> Noise -> Frame -> yamux -> bond header -> N x TCP
//!
//! Architecture:
//! N x (TCP -> bond header -> yamux)
//! Bonded into one logical (Sender, Receiver) with health-based failover.
//!
//! N is configurable (default 3, range 1-8).

mod bond;
mod config;
mod conn;
mod connector;
#[allow(dead_code)]
mod health;

pub use config::{TcpBondConfig, set_tcp_bond_config};
pub use connector::TcpBondConnector;
pub use health::BondHealthSummary;

/// Crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
