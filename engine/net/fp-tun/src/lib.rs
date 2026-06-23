// DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
// Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
// DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
// TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
// 0. You just DO WHAT THE FUCK YOU WANT TO.

// Migrated unsafe-heavy platform/FFI code; keep upstream unsafe-fn bodies as-is
// under edition 2024 rather than rewrapping every op in an inner `unsafe {}`.
#![allow(unsafe_op_in_unsafe_fn)]

mod error;
pub use crate::error::*;

mod address;
pub use crate::address::ToAddress;

#[allow(hidden_glob_reexports)]
mod device;
pub use crate::device::Device;

pub mod configuration;
pub use crate::configuration::{Configuration, Layer};

pub mod platform;
pub use crate::platform::create;

#[cfg(all(
    feature = "async",
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
    )
))]
pub mod r#async;

#[cfg(all(
    feature = "async",
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows",
    )
))]
pub use r#async::*;

pub fn configure() -> Configuration {
    Configuration::default()
}
