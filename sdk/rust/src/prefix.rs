// SPDX-License-Identifier: BSD-3-Clause
//! Semantic IP prefixes shared by coordination and consumers.

use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpPrefix {
    network: IpAddr,
    length: u8,
}

impl FromStr for IpPrefix {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, length) = match value.split_once('/') {
            Some((address, length)) => (address, Some(length.parse::<u8>().map_err(|_| "invalid prefix length")?)),
            None => (value, None),
        };
        let address: IpAddr = address.parse().map_err(|_| "invalid IP address")?;
        let length = length.unwrap_or(if address.is_ipv4() { 32 } else { 128 });
        let network = match address {
            IpAddr::V4(ip) if length <= 32 => {
                let mask = if length == 0 { 0 } else { u32::MAX << (32 - length) };
                IpAddr::V4((u32::from(ip) & mask).into())
            }
            IpAddr::V6(ip) if length <= 128 => {
                let mask = if length == 0 { 0 } else { u128::MAX << (128 - length) };
                IpAddr::V6((u128::from(ip) & mask).into())
            }
            _ => return Err("prefix length out of range"),
        };
        Ok(Self { network, length })
    }
}

impl IpPrefix {
    pub fn network(self) -> IpAddr { self.network }
    pub fn length(self) -> u8 { self.length }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.length == 0 { 0 } else { u32::MAX << (32 - self.length) };
                (u32::from(address) & mask) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.length == 0 { 0 } else { u128::MAX << (128 - self.length) };
                (u128::from(address) & mask) == u128::from(network)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_host_bits_and_default_variants_and_rejects_invalid_prefixes() {
        for (input, expected) in [("1.2.3.4/0", "0.0.0.0/0"), ("0.0.0.0/00", "0.0.0.0/0"), ("10.2.3.4/8", "10.0.0.0/8"), ("2001:db8::7/32", "2001:db8::/32"), ("::1/00", "::/0")] {
            assert_eq!(input.parse::<IpPrefix>().unwrap().to_string(), expected);
        }
        for invalid in ["1.2.3.4/33", "::/129", "x/0", "::/x", "1.2.3.4/-1"] {
            assert!(invalid.parse::<IpPrefix>().is_err());
        }
    }
}
