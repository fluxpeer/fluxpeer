//! Network-related utilities (TCP tuning)

use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

/// Enable low-latency options on a TCP stream (best-effort).
pub fn configure_tcp_stream(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        debug!("[Net] Failed to enable TCP_NODELAY for {}: {}", context, err);
    }

    #[cfg(any(unix, windows))]
    {
        use socket2::{SockRef, TcpKeepalive};

        // Aligned with client-side conn.rs: 30s/10s, matched after 2026-05-20
        // bond disconnect audit. Previous 120/30 was 4x looser than client,
        // causing the server to keep sockets the middlebox had already torn
        // down. See docs/task/09-vpn-bond-disconnect-audit.md.
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10));

        if let Err(err) = SockRef::from(stream).set_tcp_keepalive(&keepalive) {
            debug!("[Net] Failed to configure TCP keepalive for {}: {}", context, err);
        }
    }
}
