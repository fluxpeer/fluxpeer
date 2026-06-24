//! Mobile FFI for the FULL `fluxpeer-node` engine.
//!
//! A phone runs the SAME node data plane as desktop/server (disco / relay /
//! multi-peer / exit-as-a-peer), adopting the OS-provided VPN tun fd via
//! `fluxpeer_node::run_embedded`. This replaces the standalone two-phase mobile
//! dispatcher (`fp-node-client-sys`): the phone is a first-class mesh peer, not a
//! protocol-incompatible thin gateway client.
//!
//! Cross-build: `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o jniLibs
//! build --release -p fp-node-mobile-sys` → `libfp_node_mobile_sys.so` per ABI.

#[cfg(target_os = "android")]
mod android;
