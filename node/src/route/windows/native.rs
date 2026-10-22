// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use std::{net::{Ipv4Addr, Ipv6Addr}, sync::OnceLock};
use parking_lot::Mutex;
use windows::{core::PCWSTR, Win32::{Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR},
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH}, Networking::WinSock::*}};

static OWNER: OnceLock<Mutex<Book>> = OnceLock::new();
struct System;
fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code.0 == 0 { Ok(()) } else if code == ERROR_OBJECT_ALREADY_EXISTS {
        Err(io::Error::new(io::ErrorKind::AlreadyExists, "IP Helper route already exists"))
    } else { Err(io::Error::from_raw_os_error(code.0 as i32)) }
}
fn address(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(ip) => SOCKADDR_INET { Ipv4: SOCKADDR_IN { sin_family: AF_INET,
            sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(ip.octets()) } }, ..Default::default() } },
        IpAddr::V6(ip) => SOCKADDR_INET { Ipv6: SOCKADDR_IN6 { sin6_family: AF_INET6,
            sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: ip.octets() } }, ..Default::default() } },
    }
}
fn ip(address: SOCKADDR_INET) -> io::Result<IpAddr> {
    // SAFETY: si_family is the common discriminator of SOCKADDR_INET; only the
    // matching initialized IPv4/IPv6 member returned by IP Helper is read.
    unsafe {
        match address.si_family {
            AF_INET => Ok(Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()),
            AF_INET6 => Ok(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte).into()),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unknown route address family")),
        }
    }
}
fn native(row: &Row) -> io::Result<MIB_IPFORWARD_ROW2> {
    let prefix: fluxpeer_sdk::prefix::IpPrefix = row.prefix.parse().map_err(io::Error::other)?;
    let mut output = MIB_IPFORWARD_ROW2::default();
    // SAFETY: output is a writable initialized row with the expected ABI.
    unsafe { InitializeIpForwardEntry(&mut output); }
    output.InterfaceLuid = NET_LUID_LH { Value: row.luid };
    output.DestinationPrefix = IP_ADDRESS_PREFIX { Prefix: address(prefix.network()), PrefixLength: prefix.length() };
    output.NextHop = address(row.gateway); output.Metric = row.metric; output.Protocol = NL_ROUTE_PROTOCOL(row.protocol as i32);
    output.SitePrefixLength = row.site_prefix; output.ValidLifetime = row.valid; output.PreferredLifetime = row.preferred;
    output.Loopback = row.loopback; output.AutoconfigureAddress = row.autoconfigure;
    output.Publish = row.publish; output.Immortal = row.immortal;
    Ok(output)
}
fn snapshot(row: &MIB_IPFORWARD_ROW2) -> io::Result<Row> {
    let prefix = format!("{}/{}", ip(row.DestinationPrefix.Prefix)?, row.DestinationPrefix.PrefixLength);
    Ok(Row { prefix, gateway: ip(row.NextHop)?,
        // SAFETY: Value is the integer representation of a NET_LUID_LH union.
        luid: unsafe { row.InterfaceLuid.Value }, metric: row.Metric, protocol: row.Protocol.0 as u32,
        site_prefix: row.SitePrefixLength, valid: row.ValidLifetime, preferred: row.PreferredLifetime,
        loopback: row.Loopback, autoconfigure: row.AutoconfigureAddress, publish: row.Publish, immortal: row.Immortal })
}
impl Api for System {
    fn get(&mut self, row: &Row) -> io::Result<Option<Row>> {
        let mut row = native(row)?;
        // SAFETY: row contains initialized route identity and writable output fields.
        let code = unsafe { GetIpForwardEntry2(&mut row) };
        if code == ERROR_NOT_FOUND { return Ok(None); }
        check(code)?; snapshot(&row).map(Some)
    }
    fn create(&mut self, row: &Row) -> io::Result<()> {
        let row = native(row)?;
        // SAFETY: the row and its embedded addresses remain alive for this call.
        check(unsafe { CreateIpForwardEntry2(&row) })
    }
    fn delete(&mut self, row: &Row) -> io::Result<()> {
        let row = native(row)?;
        // SAFETY: the row is a verified owned route identity, with valid addresses.
        let code = unsafe { DeleteIpForwardEntry2(&row) };
        if code == ERROR_NOT_FOUND { return Err(io::ErrorKind::NotFound.into()); }
        check(code)
    }
}
fn root() -> PathBuf { crate::statusd::status_dir().join("routes") }
pub(crate) fn begin(iface: &str) -> io::Result<()> {
    let mut book = Book::open(&root(), iface)?;
    book.cleanup(&mut System)?;
    OWNER.set(Mutex::new(book)).map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "route owner already initialized"))
}
pub(crate) fn recover(iface: &str) -> io::Result<()> { Book::open(&root(), iface)?.cleanup(&mut System) }
fn with_book<T>(run: impl FnOnce(&mut Book) -> io::Result<T>) -> io::Result<T> {
    let owner = OWNER.get().ok_or_else(|| io::Error::other("route owner not initialized"))?;
    run(&mut owner.lock())
}
pub(crate) fn cleanup() -> io::Result<()> {
    match OWNER.get() { Some(book) => book.lock().cleanup(&mut System), None => Ok(()) }
}
fn luid(dev: &str) -> io::Result<u64> {
    if let Some(value) = dev.strip_prefix("luid:") { return value.parse().map_err(io::Error::other); }
    if dev.contains('\0') { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid interface alias")); }
    let alias: Vec<u16> = dev.encode_utf16().chain(Some(0)).collect();
    let mut result = NET_LUID_LH::default();
    // SAFETY: alias is NUL-terminated UTF-16; result is writable for the call.
    check(unsafe { ConvertInterfaceAliasToLuid(PCWSTR(alias.as_ptr()), &mut result) })?;
    // SAFETY: Value is the LUID's scalar representation.
    Ok(unsafe { result.Value })
}
fn key(prefix: &str, dev: Option<&str>) -> io::Result<String> {
    let prefix: fluxpeer_sdk::prefix::IpPrefix = prefix.parse().map_err(io::Error::other)?;
    Ok(match dev { Some(dev) => format!("tun/{dev}/{prefix}"), None => format!("bypass/{prefix}") })
}
pub(crate) fn add(prefix: &str, dev: &str, gateway: Option<&str>) -> io::Result<()> {
    let prefix: fluxpeer_sdk::prefix::IpPrefix = prefix.parse().map_err(io::Error::other)?;
    let hop = match gateway {
        Some(gateway) => gateway.parse().map_err(io::Error::other)?,
        None if prefix.network().is_ipv4() => Ipv4Addr::UNSPECIFIED.into(),
        None => Ipv6Addr::UNSPECIFIED.into(),
    };
    let key = key(&prefix.to_string(), gateway.is_none().then_some(dev))?;
    let row = Row::new(&prefix.to_string(), hop, luid(dev)?)?;
    with_book(|book| book.add(&key, row, &mut System))
}
pub(crate) fn remove(prefix: &str, dev: &str) -> io::Result<()> {
    let key = key(prefix, Some(dev))?; with_book(|book| book.remove(&key, &mut System))
}
pub(crate) fn remove_bypass(prefix: &str) -> io::Result<()> {
    let key = key(prefix, None)?; with_book(|book| book.remove(&key, &mut System))
}
struct Table(*mut MIB_IPFORWARD_TABLE2);
impl Drop for Table {
    fn drop(&mut self) {
        // SAFETY: IP Helper allocated this non-null table and this guard owns it.
        unsafe { FreeMibTable(self.0.cast()); }
    }
}
fn defaults(v6: bool) -> io::Result<Vec<(Row, u64)>> {
    let family = if v6 { AF_INET6 } else { AF_INET };
    let mut ptr = std::ptr::null_mut();
    // SAFETY: ptr is a writable output pointer; the returned allocation is guarded below.
    check(unsafe { GetIpForwardTable2(family, &mut ptr) })?;
    if ptr.is_null() { return Err(io::Error::other("IP Helper returned a null route table")); }
    let table = Table(ptr);
    // SAFETY: the table allocation contains NumEntries correctly aligned rows
    // beginning at Table (not immediately after NumEntries, which has padding).
    let rows = unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize) };
    let mut defaults = Vec::new();
    for row in rows.iter().filter(|row| row.DestinationPrefix.PrefixLength == 0) {
        let saved = snapshot(row)?;
        if saved.gateway.is_unspecified() { continue; }
        let mut interface = MIB_IPINTERFACE_ROW { Family: family, InterfaceLuid: row.InterfaceLuid, ..Default::default() };
        // SAFETY: initialized identity selects the matching IP interface; output is writable.
        check(unsafe { GetIpInterfaceEntry(&mut interface) })?;
        if interface.Connected { defaults.push((saved, u64::from(row.Metric) + u64::from(interface.Metric))); }
    }
    defaults.sort_by_key(|(row, metric)| (*metric, row.luid));
    Ok(defaults)
}
pub(crate) fn default_route(v6: bool) -> io::Result<Option<(String, String)>> {
    Ok(defaults(v6)?.first().map(|(row, _)| (row.gateway.to_string(), format!("luid:{}", row.luid))))
}
pub(crate) fn needs_bypass(destination: &str) -> io::Result<bool> {
    let prefix: fluxpeer_sdk::prefix::IpPrefix = destination.parse().map_err(io::Error::other)?;
    let Some((route, _)) = defaults(prefix.network().is_ipv6())?.into_iter().next() else { return Ok(false); };
    let interface = NET_LUID_LH { Value: route.luid };
    let destination = address(prefix.network()); let mut best = MIB_IPFORWARD_ROW2::default(); let mut source = SOCKADDR_INET::default();
    // SAFETY: all addresses/outputs are initialized and outlive the call. Pinning
    // the physical interface prevents our own split-default from winning lookup.
    check(unsafe { GetBestRoute2(Some(&interface), 0, None, &destination, 0, &mut best, &mut source) })?;
    Ok(!ip(best.NextHop)?.is_unspecified())
}
