//! Egress-socket protection hook (mobile).
//!
//! On Android/iOS the engine runs inside a VPN service that owns the tun. Every
//! socket the engine opens to a *real* peer/relay must be excluded from that VPN
//! (`VpnService.protect(fd)`), or its own packets route back INTO the tun — a loop
//! that black-holes exactly the relay/TCP fallback you need on cellular/CGNAT.
//!
//! The host registers one [`set_protect`] callback at startup; every TCP egress
//! site routes through [`connect_tcp`], which protects the socket BEFORE `connect`
//! so the SYN leaves on the underlying interface, not the tunnel. Desktop/server
//! never register one, so it's a no-op there.

#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::OnceLock;

/// Called with every egress socket fd so the host can exclude it from the tunnel.
/// Structurally identical to `fluxpeer_node::ProtectFn`, so the node can hand its
/// own callback straight to [`set_protect`].
#[cfg(unix)]
pub type ProtectFn = std::sync::Arc<dyn Fn(RawFd) + Send + Sync>;

#[cfg(unix)]
static PROTECT: OnceLock<ProtectFn> = OnceLock::new();

/// Register the process-wide protect callback (idempotent; one node per process).
/// No-op on non-unix — mobile (the only protect consumer) is always unix.
#[cfg(unix)]
pub fn set_protect(f: ProtectFn) {
    let _ = PROTECT.set(f);
}

/// Protect a raw fd via the registered callback, if any. Use at socket-creation
/// sites that can't go through [`connect_tcp`] (e.g. accepted inbound streams).
#[cfg(unix)]
pub fn protect_fd(fd: RawFd) {
    if let Some(p) = PROTECT.get() {
        p(fd);
    }
}

/// No-op on non-unix targets.
#[cfg(not(unix))]
pub fn protect_fd(_fd: i32) {}

/// Open a TCP connection, protecting the socket from the VPN tunnel *before* the
/// connect handshake. Mirrors `TcpStream::connect` semantics; on desktop/server
/// (no registered callback) it's an ordinary connect.
pub async fn connect_tcp(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let sock = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        protect_fd(sock.as_raw_fd());
    }
    sock.connect(addr).await
}
