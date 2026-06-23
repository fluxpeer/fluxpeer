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

//! Platform specific modules.

#[cfg(unix)]
pub mod posix;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::{Configuration, Device, Queue, create};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::{Configuration, Device, Queue, create};

#[cfg(target_os = "ios")]
pub mod ios;
#[cfg(target_os = "ios")]
pub use self::ios::{Configuration, Device, Queue, create};

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
pub use self::android::{Configuration, Device, Queue, create};

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::{Configuration, Device, Queue, create};

#[cfg(test)]
mod test {
    use crate::configuration::Configuration;
    use crate::device::Device;
    use std::net::Ipv4Addr;

    #[test]
    #[ignore = "requires root/elevated privileges to create a real TUN device"]
    fn create() {
        let dev = super::create(
            Configuration::default()
                .name("utun6")
                .address("192.168.50.1")
                .netmask("255.255.0.0")
                .mtu(1400)
                .up(),
        )
        .unwrap();

        assert_eq!("192.168.50.1".parse::<Ipv4Addr>().unwrap(), dev.address().unwrap());

        assert_eq!("255.255.0.0".parse::<Ipv4Addr>().unwrap(), dev.netmask().unwrap());

        assert_eq!(1400, dev.mtu().unwrap());
    }
}
