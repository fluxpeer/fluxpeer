//! fluxpeer protocol versioning.
//!
//! Three independently-versioned protocols plus a minimum-supported floor for
//! each, and a config epoch used by the coordination plane for hot updates.
//!
//! Bump rules:
//! - increment the relevant `*_PROTOCOL_VERSION` on ANY wire-format change;
//! - raise a `MIN_SUPPORTED_*` only when intentionally dropping backward
//!   compatibility with older peers.
//!
//! The control-plane API version (`server_api_version`) and the relay protocol
//! are documented in `api-schema/PROTOCOL_VERSIONING.md`; the constants below are
//! the data-plane source of truth shared by the engine.

/// Data-plane protocol a client advertises in the handshake frame.
pub const CLIENT_PROTOCOL_VERSION: u32 = 1;
/// Data-plane protocol the node/relay server side speaks.
pub const SERVER_PROTOCOL_VERSION: u32 = 1;
/// Relay protocol version (DERP-style relay).
pub const RELAY_PROTOCOL_VERSION: u32 = 1;

/// Oldest client protocol version the server still accepts.
pub const MIN_SUPPORTED_CLIENT_PROTOCOL_VERSION: u32 = 1;
/// Oldest server protocol version a client still accepts.
pub const MIN_SUPPORTED_SERVER_PROTOCOL_VERSION: u32 = 1;

/// A peer that did not advertise a version (predates versioning / unknown).
pub const PROTOCOL_VERSION_UNKNOWN: u32 = 0;

/// Monotonic config epoch type used by the coordination plane: every config
/// push carries an epoch; clients only apply strictly-newer epochs and force a
/// full sync on reconnect to converge. (Wire/storage lives in control-server.)
pub type ConfigEpoch = u64;

/// Whether a peer-advertised client protocol version is acceptable to a server.
#[inline]
pub fn client_version_supported(v: u32) -> bool {
    v >= MIN_SUPPORTED_CLIENT_PROTOCOL_VERSION
}

/// Whether a peer-advertised server protocol version is acceptable to a client.
#[inline]
pub fn server_version_supported(v: u32) -> bool {
    v >= MIN_SUPPORTED_SERVER_PROTOCOL_VERSION
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn current_versions_are_self_supported() {
        assert!(client_version_supported(CLIENT_PROTOCOL_VERSION));
        assert!(server_version_supported(SERVER_PROTOCOL_VERSION));
    }

    #[test]
    fn unknown_version_is_rejected() {
        assert!(!client_version_supported(PROTOCOL_VERSION_UNKNOWN));
    }
}
