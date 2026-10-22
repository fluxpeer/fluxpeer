// SPDX-License-Identifier: BSD-3-Clause
//! Scheme C: resolve before arming; retained guards resolve only from private pins
//! until an authenticated exit and its routes/DNS are available.
use std::{collections::{BTreeMap, BTreeSet}, io::{self, Read, Write}, net::{IpAddr, SocketAddr}, path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicU8, Ordering}}, time::Duration};

pub(crate) const ROOT: &str = "/run/fluxpeer-firewall";
const BOOTSTRAP: u8 = 0;
const LOCKED: u8 = 1;
const EXIT_READY: u8 = 2;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Entry { addresses: Vec<IpAddr>, updated_at: u64 }
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Pins { hosts: BTreeMap<String, Entry> }
pub(crate) struct Cache {
    path: PathBuf,
    pins: parking_lot::RwLock<Pins>,
    mode: AtomicU8,
    missing: parking_lot::Mutex<BTreeSet<String>>,
    failed: parking_lot::Mutex<BTreeSet<IpAddr>>,
}
pub(crate) fn blocked(host: &str) -> io::Error { io::Error::other(format!("kill_switch_dns_blocked: {host}; connect an exit or disable kill-switch")) }
pub(crate) fn is_blocked(error: &io::Error) -> bool { error.to_string().contains("kill_switch_dns_blocked:") }
pub(crate) fn cache_path(root: &Path, iface: &str) -> io::Result<PathBuf> {
    if !crate::daemon::valid_iface(iface) { return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid carrier cache interface")); }
    Ok(root.join(format!("{iface}.carriers.json")))
}
/// O_NOFOLLOW also protects reads during atomic replacement. Reject special
/// files and lax permissions before reading bytes; never follow a cache symlink.
pub(crate) fn read_private(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut options = std::fs::OpenOptions::new(); options.read(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK); }
    let file = match options.open(path) { Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None), result => result? };
    let meta = file.metadata()?;
    if !meta.is_file() { return Err(io::Error::other("carrier cache is not a regular file")); }
    #[cfg(unix)]
    { use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o777 != 0o600 { return Err(io::Error::new(io::ErrorKind::PermissionDenied, "carrier cache must have mode 0600")); }
    }
    let mut bytes = Vec::new(); file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 { return Err(io::Error::other("carrier cache exceeds size limit")); }
    Ok(Some(bytes))
}
#[cfg(any(target_os = "linux", test))]
pub(crate) fn remove_at(root: &Path, iface: &str) -> io::Result<()> {
    let path = cache_path(root, iface)?;
    // Refuse a foreign symlink/special file rather than deleting its target.
    if read_private(&path)?.is_some() { std::fs::remove_file(path)?; }
    Ok(())
}
impl Cache {
    pub fn open(root: &Path, iface: &str, retained: bool) -> io::Result<Arc<Self>> {
        let path = cache_path(root, iface)?;
        let saved = read_private(&path)?;
        let pins: Pins = if retained { saved.map(|bytes| serde_json::from_slice(&bytes).map_err(io::Error::other)).transpose()?.unwrap_or_default() } else { Pins::default() };
        for (host, entry) in &pins.hosts {
            if host != &canonical(host) || entry.addresses.is_empty() || entry.addresses.len() > 64 { return Err(io::Error::other("invalid carrier cache entry")); }
        }
        Ok(Arc::new(Self { path, pins: parking_lot::RwLock::new(pins), mode: AtomicU8::new(if retained { LOCKED } else { BOOTSTRAP }), missing: parking_lot::Mutex::default(), failed: parking_lot::Mutex::default() }))
    }
    pub fn arm(&self) { self.exit_ready(false); }
    pub fn exit_ready(&self, ready: bool) { let _pins = self.pins.write(); self.mode.store(if ready { EXIT_READY } else { LOCKED }, Ordering::Release); }
    pub fn cache_only(&self) -> bool { self.mode.load(Ordering::Acquire) == LOCKED }
    pub fn begin_refresh(&self) { self.missing.lock().clear(); }
    pub fn addresses(&self) -> Vec<String> {
        self.pins.read().hosts.values().flat_map(|entry| entry.addresses.iter().map(ToString::to_string)).collect::<BTreeSet<_>>().into_iter().collect()
    }
    pub fn cached(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() { return Ok(vec![ip]); }
        let host = canonical(host);
        if let Some(entry) = self.pins.read().hosts.get(&host) { return Ok(entry.addresses.clone()); }
        self.missing.lock().insert(host.clone()); Err(blocked(&host))
    }
    pub async fn resolve(self: &Arc<Self>, host: &str) -> io::Result<Vec<IpAddr>> {
        self.resolve_with(host, |host| async move {
            tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host.as_str(), 0))).await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "carrier DNS timeout"))?
                .map(|ips| ips.map(|a| a.ip()).collect())
        }).await
    }
    pub(crate) async fn resolve_with<F, Fut>(self: &Arc<Self>, host: &str, resolve: F) -> io::Result<Vec<IpAddr>>
    where F: FnOnce(String) -> Fut, Fut: std::future::Future<Output = io::Result<Vec<IpAddr>>> {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() { return Ok(vec![ip]); }
        let host = canonical(host);
        if self.cache_only() { return self.cached(&host); }
        let mut addresses = resolve(host.clone()).await?;
        addresses.sort(); addresses.dedup();
        if addresses.is_empty() || addresses.len() > 64 { return Err(io::Error::other("invalid carrier DNS answer count")); }
        // If the exit disappeared while DNS was outstanding, discard its result.
        // No caller can publish unapproved physical DNS data after this transition.
        if self.cache_only() { return self.cached(&host); }
        let cache = self.clone(); let saved = addresses.clone();
        crate::apply::blocking(move || cache.record(&host, saved).map_err(Into::into)).await.map_err(Into::into)
    }
    pub async fn endpoint(self: &Arc<Self>, endpoint: &str) -> io::Result<Vec<SocketAddr>> {
        let (host, port) = endpoint_parts(endpoint)?;
        Ok(self.resolve(&host).await?.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
    }
    fn record(&self, host: &str, addresses: Vec<IpAddr>) -> io::Result<Vec<IpAddr>> {
        // Serialize publishing with exit loss, including the spawn_blocking gap.
        let mut pins = self.pins.write();
        if self.cache_only() {
            if let Some(entry) = pins.hosts.get(host) { return Ok(entry.addresses.clone()); }
            self.missing.lock().insert(host.into()); return Err(blocked(host));
        }
        let parent = self.path.parent().ok_or_else(|| io::Error::other("missing cache parent"))?;
        std::fs::create_dir_all(parent)?;
        read_private(&self.path)?;
        let old = pins.hosts.insert(host.into(), Entry { addresses: addresses.clone(), updated_at: crate::status::now_unix() });
        let result = (|| {
            let mut temp = tempfile::NamedTempFile::new_in(parent)?;
            #[cfg(unix)]
            { use std::os::unix::fs::PermissionsExt; temp.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))?; }
            temp.write_all(&serde_json::to_vec(&*pins).map_err(io::Error::other)?)?;
            temp.as_file().sync_all()?;
            temp.persist(&self.path).map_err(|e| e.error)?;
            std::fs::File::open(parent)?.sync_all()
        })();
        if result.is_err() { if let Some(old) = old { pins.hosts.insert(host.into(), old); } else { pins.hosts.remove(host); } }
        else { self.missing.lock().remove(host); }
        result.map(|()| addresses)
    }
    pub fn failed_addresses(&self, addresses: impl IntoIterator<Item = IpAddr>) { self.failed.lock().extend(addresses); }
    pub fn connected(&self, addresses: impl IntoIterator<Item = IpAddr>) { let mut failed = self.failed.lock(); for ip in addresses { failed.remove(&ip); } }
    pub fn diagnostic(&self) -> Option<String> {
        let pins = self.pins.read();
        let mut missing = self.missing.lock().clone();
        if self.cache_only() {
            let failed = self.failed.lock();
            missing.extend(pins.hosts.iter().filter(|(_, entry)| !entry.addresses.is_empty() && entry.addresses.iter().all(|ip| failed.contains(ip))).map(|(host, _)| host.clone()));
        }
        missing.into_iter().next().map(|host| blocked(&host).to_string())
    }
    pub fn network_error(&self, host: &str, error: io::Error) -> io::Error {
        if self.cache_only() && matches!(error.kind(), io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut | io::ErrorKind::NotConnected) {
            if let Ok(ips) = self.cached(host) { self.failed_addresses(ips); }
            blocked(host)
        } else { error }
    }
}
fn canonical(host: &str) -> String { host.trim_end_matches('.').to_ascii_lowercase() }
pub(crate) fn endpoint_parts(endpoint: &str) -> io::Result<(String, u16)> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() { return Ok((addr.ip().to_string(), addr.port())); }
    let url = reqwest::Url::parse(&format!("http://{endpoint}")).map_err(io::Error::other)?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() { return Err(io::Error::other("invalid carrier endpoint")); }
    Ok((url.host_str().ok_or_else(|| io::Error::other("missing carrier host"))?.trim_matches(['[', ']']).to_string(), url.port_or_known_default().ok_or_else(|| io::Error::other("missing carrier port"))?))
}

#[cfg(test)]
#[path = "carriers_tests.rs"]
mod tests;
