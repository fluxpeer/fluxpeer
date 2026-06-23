//! Centralized overlay IP allocation (IPAM).
//!
//! Per
//! plane allocates **stable** dual-stack addresses from the network's pools,
//! honoring the reserved host ranges. One host id is shared by the v4 and
//! v6 address of a device, so `.101` pairs with `…:1::101`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Reserved host octets within a network's IPv4 /24.
pub const GATEWAY_HOST: u8 = 1; // .1  virtual-router / gateway
pub const DNS_HOST: u8 = 2; // .2  MagicDNS
/// General device range `.100..=.249`; 150 usable host ids.
pub const DEVICE_HOST_MIN: u8 = 100;
pub const DEVICE_HOST_MAX: u8 = 249;
/// IPv6 subnet group used for device addresses (`…:1::host`).
const V6_DEVICE_SUBNET: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpamError {
    /// No free host id remains in the device range.
    PoolExhausted,
}

/// Per-network dual-stack allocator over a /24 IPv4 base and a /48 IPv6 ULA.
pub struct Ipam {
    v4_net: [u8; 4],     // network base; host octet (index 3) is overwritten
    v6_prefix: [u16; 3], // first 48 bits of the ULA /48
    by_key: HashMap<String, u8>,
    used: [bool; 256],
}

impl Ipam {
    /// `v4_net` is the network base (host octet ignored), `v6_prefix` the /48.
    pub fn new(v4_net: Ipv4Addr, v6_prefix: [u16; 3]) -> Self {
        Self {
            v4_net: v4_net.octets(),
            v6_prefix,
            by_key: HashMap::new(),
            used: [false; 256],
        }
    }

    fn v4_for(&self, host: u8) -> Ipv4Addr {
        Ipv4Addr::new(self.v4_net[0], self.v4_net[1], self.v4_net[2], host)
    }

    fn v6_for(&self, host: u8) -> Ipv6Addr {
        let [a, b, c] = self.v6_prefix;
        Ipv6Addr::new(a, b, c, V6_DEVICE_SUBNET, 0, 0, 0, host as u16)
    }

    /// Allocate (or return the existing, stable) dual-stack address for a device
    /// identified by its public key. Re-allocation is idempotent (stable).
    pub fn allocate(&mut self, pubkey: &str) -> Result<(Ipv4Addr, Ipv6Addr), IpamError> {
        if let Some(&host) = self.by_key.get(pubkey) {
            return Ok((self.v4_for(host), self.v6_for(host)));
        }
        let host = (DEVICE_HOST_MIN..=DEVICE_HOST_MAX)
            .find(|&h| !self.used[h as usize])
            .ok_or(IpamError::PoolExhausted)?;
        self.used[host as usize] = true;
        self.by_key.insert(pubkey.to_string(), host);
        Ok((self.v4_for(host), self.v6_for(host)))
    }

    /// Claim a *specific* host id for a device (batch import preserves the fixed
    /// addresses from a wg.conf rather than auto-allocating). Idempotent per key;
    /// returns `Err(PoolExhausted)` if the host is already taken by another device.
    pub fn reserve(&mut self, pubkey: &str, host: u8) -> Result<(), IpamError> {
        if self.by_key.get(pubkey) == Some(&host) {
            return Ok(());
        }
        if self.used[host as usize] {
            return Err(IpamError::PoolExhausted);
        }
        self.used[host as usize] = true;
        self.by_key.insert(pubkey.to_string(), host);
        Ok(())
    }

    /// Release a device's address back to the pool. Returns true if freed.
    pub fn recycle(&mut self, pubkey: &str) -> bool {
        if let Some(host) = self.by_key.remove(pubkey) {
            self.used[host as usize] = false;
            true
        } else {
            false
        }
    }

    /// Number of device addresses currently allocated.
    pub fn allocated_count(&self) -> usize {
        self.by_key.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn ipam() -> Ipam {
        // 100.72.15.0/24 + fd72:15ab:c901::/48
        Ipam::new(Ipv4Addr::new(100, 72, 15, 0), [0xfd72, 0x15ab, 0xc901])
    }

    #[test]
    fn first_device_starts_at_100_and_pairs_v4_v6() {
        let mut a = ipam();
        let (v4, v6) = a.allocate("dev-a").unwrap();
        assert_eq!(v4, Ipv4Addr::new(100, 72, 15, 100));
        assert_eq!(v6, "fd72:15ab:c901:1::64".parse::<Ipv6Addr>().unwrap()); // 0x64 = 100
    }

    #[test]
    fn allocation_is_stable_per_key() {
        let mut a = ipam();
        let first = a.allocate("dev-a").unwrap();
        let _other = a.allocate("dev-b").unwrap();
        let again = a.allocate("dev-a").unwrap();
        assert_eq!(first, again);
        assert_eq!(a.allocated_count(), 2);
    }

    #[test]
    fn reserved_low_hosts_are_never_handed_out() {
        let mut a = ipam();
        for i in 0..50 {
            let (v4, _) = a.allocate(&format!("d{i}")).unwrap();
            assert!(v4.octets()[3] >= DEVICE_HOST_MIN);
            assert_ne!(v4.octets()[3], GATEWAY_HOST);
            assert_ne!(v4.octets()[3], DNS_HOST);
        }
    }

    #[test]
    fn pool_exhausts_after_150_devices() {
        let mut a = ipam();
        let capacity = (DEVICE_HOST_MAX - DEVICE_HOST_MIN + 1) as usize; // 150
        for i in 0..capacity {
            assert!(a.allocate(&format!("d{i}")).is_ok());
        }
        assert_eq!(a.allocate("overflow"), Err(IpamError::PoolExhausted));
    }

    #[test]
    fn recycle_frees_and_reuses_lowest() {
        let mut a = ipam();
        let (v4_first, _) = a.allocate("dev-a").unwrap(); // .100
        let _ = a.allocate("dev-b").unwrap(); // .101
        assert!(a.recycle("dev-a"));
        // freed.100 is the lowest free host, so next new device reuses it
        let (v4_new, _) = a.allocate("dev-c").unwrap();
        assert_eq!(v4_new, v4_first);
        assert!(!a.recycle("dev-a")); // already gone
    }
}
