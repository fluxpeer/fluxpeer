/// A trie of IP/cidr addresses
pub struct IpTable<D> {
    ips: ip_network_table::IpNetworkTable<D>,
}

impl<T> Default for IpTable<T> {
    fn default() -> Self {
        Self {
            ips: ip_network_table::IpNetworkTable::new(),
        }
    }
}

impl<'a, D> FromIterator<(&'a crate::AllowedIP, D)> for IpTable<D> {
    fn from_iter<I: IntoIterator<Item = (&'a crate::AllowedIP, D)>>(iter: I) -> Self {
        let mut ip_table = IpTable::new();

        for (ip, data) in iter {
            ip_table.insert(ip.addr, ip.cidr as u32, data);
        }

        ip_table
    }
}

impl<D> IpTable<D> {
    pub fn new() -> Self {
        Self {
            ips: ip_network_table::IpNetworkTable::new(),
        }
    }

    #[allow(unused)]
    pub fn clear(&mut self) {
        self.ips = ip_network_table::IpNetworkTable::new();
    }

    pub fn insert(&mut self, key: std::net::IpAddr, cidr: u32, data: D) -> Option<D> {
        // These are networks, it doesn't make sense for host bits to be set, so
        // use new_truncate().
        self.ips.insert(
            ip_network::IpNetwork::new_truncate(key, cidr as u8).expect("cidr is valid length"),
            data,
        )
    }

    #[allow(unused)]
    pub fn find(&self, key: std::net::IpAddr) -> Option<&D> {
        self.ips.longest_match(key).map(|(_net, data)| data)
    }

    #[allow(unused)]
    pub fn find_mut(&mut self, key: std::net::IpAddr) -> Option<&mut D> {
        self.ips.longest_match_mut(key).map(|(_net, data)| data)
    }

    #[allow(unused)]
    pub fn remove(&mut self, predicate: &dyn Fn(&D) -> bool) {
        self.ips.retain(|_, v| !predicate(v));
    }

    pub fn iter(&self) -> Iter<'_, D> {
        Iter(
            self.ips
                .iter()
                .map(|(ipa, d)| (d, ipa.network_address(), ipa.netmask()))
                .collect(),
        )
    }
}

pub struct Iter<'a, D: 'a>(std::collections::VecDeque<(&'a D, std::net::IpAddr, u8)>);

impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, std::net::IpAddr, u8);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_allowed_ips() -> IpTable<char> {
        let mut map: IpTable<char> = Default::default();
        map.insert(std::net::IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(std::net::IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(std::net::IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(std::net::IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(std::net::IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(std::net::IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(std::net::IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        map
    }

    #[test]
    fn test_allowed_ips_insert_find() {
        let map = build_allowed_ips();
        assert_eq!(map.find(std::net::IpAddr::from([127, 0, 0, 1])), Some(&'1'));
        assert_eq!(map.find(std::net::IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(std::net::IpAddr::from([127, 1, 255, 255])), None);
        assert_eq!(map.find(std::net::IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(std::net::IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(std::net::IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(std::net::IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(std::net::IpAddr::from([255, 1, 15, 2])), Some(&'4'));
        assert_eq!(map.find(std::net::IpAddr::from([60, 25, 15, 1])), Some(&'5'));
        assert_eq!(map.find(std::net::IpAddr::from([20, 0, 0, 100])), None);
        assert_eq!(map.find(std::net::IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0])), Some(&'7'));
        assert_eq!(map.find(std::net::IpAddr::from([553, 0, 0, 1, 0, 0, 0, 1])), None);
        assert_eq!(map.find(std::net::IpAddr::from([45, 25, 15, 1])), Some(&'6'));
    }

    #[test]
    fn test_allowed_ips_remove() {
        let mut map = build_allowed_ips();
        map.remove(&|c| *c == '5' || *c == '1' || *c == '7');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', std::net::IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', std::net::IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', std::net::IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', std::net::IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_allowed_ips_iter() {
        let map = build_allowed_ips();
        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', std::net::IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'5', std::net::IpAddr::from([60, 25, 15, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', std::net::IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'1', std::net::IpAddr::from([127, 0, 0, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', std::net::IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', std::net::IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'7', std::net::IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_allowed_ips_v4_kernel_compatibility() {
        // Test case from wireguard-go
        let mut map: IpTable<char> = Default::default();

        map.insert(std::net::IpAddr::from([192, 168, 4, 0]), 24, 'a');
        map.insert(std::net::IpAddr::from([192, 168, 4, 4]), 32, 'b');
        map.insert(std::net::IpAddr::from([192, 168, 0, 0]), 16, 'c');
        map.insert(std::net::IpAddr::from([192, 95, 5, 64]), 27, 'd');
        map.insert(std::net::IpAddr::from([192, 95, 5, 65]), 27, 'c');
        map.insert(std::net::IpAddr::from([0, 0, 0, 0]), 0, 'e');
        map.insert(std::net::IpAddr::from([64, 15, 112, 0]), 20, 'g');
        map.insert(std::net::IpAddr::from([64, 15, 123, 211]), 25, 'h');
        map.insert(std::net::IpAddr::from([10, 0, 0, 0]), 25, 'a');
        map.insert(std::net::IpAddr::from([10, 0, 0, 128]), 25, 'b');
        map.insert(std::net::IpAddr::from([10, 1, 0, 0]), 30, 'a');
        map.insert(std::net::IpAddr::from([10, 1, 0, 4]), 30, 'b');
        map.insert(std::net::IpAddr::from([10, 1, 0, 8]), 29, 'c');
        map.insert(std::net::IpAddr::from([10, 1, 0, 16]), 29, 'd');

        assert_eq!(Some(&'a'), map.find(std::net::IpAddr::from([192, 168, 4, 20])));
        assert_eq!(Some(&'a'), map.find(std::net::IpAddr::from([192, 168, 4, 0])));
        assert_eq!(Some(&'b'), map.find(std::net::IpAddr::from([192, 168, 4, 4])));
        assert_eq!(Some(&'c'), map.find(std::net::IpAddr::from([192, 168, 200, 182])));
        assert_eq!(Some(&'c'), map.find(std::net::IpAddr::from([192, 95, 5, 68])));
        assert_eq!(Some(&'e'), map.find(std::net::IpAddr::from([192, 95, 5, 96])));
        assert_eq!(Some(&'g'), map.find(std::net::IpAddr::from([64, 15, 116, 26])));
        assert_eq!(Some(&'g'), map.find(std::net::IpAddr::from([64, 15, 127, 3])));

        map.insert(std::net::IpAddr::from([1, 0, 0, 0]), 32, 'a');
        map.insert(std::net::IpAddr::from([64, 0, 0, 0]), 32, 'a');
        map.insert(std::net::IpAddr::from([128, 0, 0, 0]), 32, 'a');
        map.insert(std::net::IpAddr::from([192, 0, 0, 0]), 32, 'a');
        map.insert(std::net::IpAddr::from([255, 0, 0, 0]), 32, 'a');

        assert_eq!(Some(&'a'), map.find(std::net::IpAddr::from([1, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(std::net::IpAddr::from([64, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(std::net::IpAddr::from([128, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(std::net::IpAddr::from([192, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(std::net::IpAddr::from([255, 0, 0, 0])));

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(std::net::IpAddr::from([1, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(std::net::IpAddr::from([64, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(std::net::IpAddr::from([128, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(std::net::IpAddr::from([192, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(std::net::IpAddr::from([255, 0, 0, 0])));

        map.clear();

        map.insert(std::net::IpAddr::from([192, 168, 0, 0]), 16, 'a');
        map.insert(std::net::IpAddr::from([192, 168, 0, 0]), 24, 'a');

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(std::net::IpAddr::from([192, 168, 0, 1])));
    }

    #[test]
    fn test_allowed_ips_v6_kernel_compatibility() {
        // Test case from wireguard-go
        let mut map: IpTable<char> = Default::default();

        map.insert(
            std::net::IpAddr::from([0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543]),
            128,
            'd',
        );
        map.insert(
            std::net::IpAddr::from([0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0x0000, 0x0000]),
            64,
            'c',
        );
        map.insert(
            std::net::IpAddr::from([0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]),
            0,
            'e',
        );
        map.insert(
            std::net::IpAddr::from([0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]),
            0,
            'f',
        );
        map.insert(
            std::net::IpAddr::from([0x2404, 0x6800, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]),
            32,
            'g',
        );
        map.insert(
            std::net::IpAddr::from([0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef]),
            64,
            'h',
        );
        map.insert(
            std::net::IpAddr::from([0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef]),
            128,
            'a',
        );
        map.insert(
            std::net::IpAddr::from([0x2444, 0x6800, 0x40e4, 0x0800, 0xdeae, 0xbeef, 0x0def, 0xbeef]),
            128,
            'c',
        );
        map.insert(
            std::net::IpAddr::from([0x2444, 0x6800, 0xf0e4, 0x0800, 0xeeae, 0xbeef, 0x0000, 0x0000]),
            98,
            'b',
        );

        assert_eq!(
            Some(&'d'),
            map.find(std::net::IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543
            ]))
        );
        assert_eq!(
            Some(&'c'),
            map.find(std::net::IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0xc02e, 0x01ee
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(std::net::IpAddr::from([0x2607, 0x5300, 0x6000, 0x6b01, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(std::net::IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0, 0, 0x1006
            ]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(std::net::IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(std::net::IpAddr::from([
                0x2404, 0x67ff, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(std::net::IpAddr::from([
                0x2404, 0x6801, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(std::net::IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(std::net::IpAddr::from([0x2404, 0x6800, 0x4004, 0x0800, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(std::net::IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0x1010, 0x1010, 0x1010, 0x1010
            ]))
        );
        assert_eq!(
            Some(&'a'),
            map.find(std::net::IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef
            ]))
        );
    }

    #[test]
    fn test_allowed_ips_iter_zero_leaf_bits() {
        let mut map: IpTable<char> = Default::default();
        map.insert(std::net::IpAddr::from([10, 111, 0, 1]), 32, '1');
        map.insert(std::net::IpAddr::from([10, 111, 0, 2]), 32, '2');
        map.insert(std::net::IpAddr::from([10, 111, 0, 3]), 32, '3');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'1', std::net::IpAddr::from([10, 111, 0, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', std::net::IpAddr::from([10, 111, 0, 2]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', std::net::IpAddr::from([10, 111, 0, 3]), 32))
        );
        assert_eq!(map_iter.next(), None);
    }
}
