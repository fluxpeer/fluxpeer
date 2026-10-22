// SPDX-License-Identifier: BSD-3-Clause
//! Relay identity proofs and per-bond link authentication. Credentials are scoped
//! to a dial/listener; no process-global client key or public-name-derived secret.
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::sync::{Arc, Weak, atomic::{AtomicU64, Ordering}};
use fp_crypto::x25519::{PublicKey, StaticSecret};
use fp_transport::link::{LinkAuthenticator, LinkIo, LinkSession, Session as LinkSessionRef, denied};
use hmac::{Mac, SimpleHmac};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

type Hmac = SimpleHmac<blake2::Blake2s256>;
const AUTH: &[u8] = b"fluxpeer-relay-auth-v1";
const LINK: &[u8] = b"fluxpeer-relay-link-v1";

fn mac(key: &[u8], parts: &[&[u8]]) -> io::Result<Hmac> {
    let mut mac = Hmac::new_from_slice(key).map_err(|_| denied("invalid MAC key"))?;
    for part in parts { mac.update(part); }
    Ok(mac)
}
fn tag(key: &[u8], parts: &[&[u8]]) -> io::Result<[u8; 32]> { Ok(mac(key, parts)?.finalize().into_bytes().into()) }
fn shared(secret: &StaticSecret, peer: [u8; 32]) -> io::Result<fp_crypto::x25519::SharedSecret> {
    let value = secret.diffie_hellman(&PublicKey::from(peer));
    if !value.was_contributory() { return Err(denied("non-contributory relay identity")); }
    Ok(value)
}
fn nonce() -> io::Result<[u8; 32]> {
    let mut value = [0; 32]; getrandom::getrandom(&mut value).map_err(io::Error::other)?; Ok(value)
}

pub struct Session {
    peer: [u8; 32],
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
}
impl LinkSession for Session {
    fn peer(&self) -> [u8; 32] { self.peer }
    fn active(&self) -> bool { self.key.lock().is_some() }
    fn invalidate(&self) { self.key.lock().take(); }
}
impl Session {
    fn new(peer: [u8; 32], key: [u8; 32]) -> Arc<Self> { Arc::new(Self { peer, key: Mutex::new(Some(Zeroizing::new(key))) }) }
    fn confirmation(&self, bond: &[u8; 16], index: u32, nonce: &[u8; 32]) -> io::Result<[u8; 32]> {
        let guard = self.key.lock(); let key = guard.as_ref().ok_or_else(|| denied("revoked bond key"))?;
        tag(key.as_ref(), &[b"fluxpeer-relay-confirm-v1", bond, &index.to_be_bytes(), nonce])
    }
    fn verify_confirmation(&self, bond: &[u8; 16], index: u32, nonce: &[u8; 32], proof: &[u8; 32]) -> io::Result<()> {
        let guard = self.key.lock(); let key = guard.as_ref().ok_or_else(|| denied("revoked bond key"))?;
        mac(key.as_ref(), &[b"fluxpeer-relay-confirm-v1", bond, &index.to_be_bytes(), nonce])?.verify_slice(proof).map_err(|_| denied("invalid relay key confirmation"))
    }
    fn proof(&self, nonce: &[u8; 32], bond: &[u8; 16], index: u32) -> io::Result<[u8; 32]> {
        let guard = self.key.lock(); let key = guard.as_ref().ok_or_else(|| denied("revoked bond key"))?;
        tag(key.as_ref(), &[nonce, bond, &index.to_be_bytes()])
    }
    fn verify(&self, nonce: &[u8; 32], bond: &[u8; 16], index: u32, proof: &[u8; 32]) -> io::Result<()> {
        let guard = self.key.lock(); let key = guard.as_ref().ok_or_else(|| denied("revoked bond key"))?;
        mac(key.as_ref(), &[nonce, bond, &index.to_be_bytes()])?.verify_slice(proof).map_err(|_| denied("invalid bond link proof"))
    }
}

#[derive(Default)]
struct Registry { groups: HashMap<[u8; 16], Weak<Session>>, pending: HashSet<[u8; 16]> }
struct Reservation<'a> { registry: &'a Mutex<Registry>, bond: [u8; 16] }
impl Drop for Reservation<'_> { fn drop(&mut self) { self.registry.lock().pending.remove(&self.bond); } }

pub struct ServerAuth {
    secret: StaticSecret,
    registry: Mutex<Registry>,
    rejected: AtomicU64,
}
impl ServerAuth {
    pub fn new(secret: StaticSecret) -> Self { Self { secret, registry: Mutex::default(), rejected: AtomicU64::new(0) } }
    pub fn public_key(&self) -> [u8; 32] { PublicKey::from(&self.secret).to_bytes() }
    pub fn rejected_links(&self) -> u64 { self.rejected.load(Ordering::Relaxed) }

    async fn primary(&self, io: &mut dyn LinkIo, bond: [u8; 16]) -> io::Result<Arc<Session>> {
        if io.read_u32().await? != 2 { return Err(denied("unsupported relay protocol version; version 2 required")); }
        let mut peer = [0; 32]; io.read_exact(&mut peer).await?;
        let shared = shared(&self.secret, peer)?;
        let challenge = nonce()?;
        io.write_all(&challenge).await?; io.flush().await?;
        let mut proof = [0; 32]; io.read_exact(&mut proof).await?;
        mac(shared.as_bytes(), &[AUTH, &challenge, &peer])?.verify_slice(&proof).map_err(|_| denied("invalid relay identity proof"))?;
        Ok(Session::new(peer, tag(shared.as_bytes(), &[LINK, &bond, &challenge])?))
    }
    pub async fn plain(&self, io: &mut dyn LinkIo) -> io::Result<LinkSessionRef> {
        let session = match self.primary(io, [0; 16]).await {
            Ok(session) => session,
            Err(error) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, "relay authentication rejected");
                return Err(error);
            }
        };
        io.write_all(&session.confirmation(&[0; 16], 0, &[0; 32])?).await?; io.flush().await?; Ok(session)
    }
    async fn accept(&self, io: &mut dyn LinkIo, bond: [u8; 16], index: u32) -> io::Result<LinkSessionRef> {
        if index == 0 {
            {
                let mut registry = self.registry.lock();
                registry.groups.retain(|_, weak| weak.upgrade().is_some_and(|s| s.active()));
                if registry.groups.contains_key(&bond) || !registry.pending.insert(bond) { return Err(denied("bond already exists or is authenticating")); }
            }
            let _reservation = Reservation { registry: &self.registry, bond };
            let session = self.primary(io, bond).await?;
            self.registry.lock().groups.insert(bond, Arc::downgrade(&session));
            io.write_all(&session.confirmation(&bond, index, &[0; 32])?).await?; io.flush().await?; Ok(session)
        } else {
            // No waiting or group creation for an unauthenticated secondary.
            let session = self.registry.lock().groups.get(&bond).and_then(Weak::upgrade)
                .filter(|s| s.active()).ok_or_else(|| denied("bond is not authenticated"))?;
            let challenge = nonce()?;
            io.write_all(&challenge).await?; io.flush().await?;
            let mut proof = [0; 32]; io.read_exact(&mut proof).await?;
            session.verify(&challenge, &bond, index, &proof)?;
            io.write_all(&session.confirmation(&bond, index, &challenge)?).await?; io.flush().await?; Ok(session)
        }
    }
}
#[async_trait::async_trait]
impl LinkAuthenticator for ServerAuth {
    async fn client(&self, _: &mut dyn LinkIo, _: [u8; 16], _: u32) -> io::Result<LinkSessionRef> { Err(denied("server authenticator used as client")) }
    async fn server(&self, io: &mut dyn LinkIo, bond: [u8; 16], index: u32) -> io::Result<LinkSessionRef> {
        let result = self.accept(io, bond, index).await;
        if let Err(error) = &result { self.rejected.fetch_add(1, Ordering::Relaxed); tracing::warn!(%error, index, "relay link authentication rejected"); }
        result
    }
}

pub struct ClientAuth {
    secret: StaticSecret,
    relay: [u8; 32],
    group: Mutex<Option<([u8; 16], Arc<Session>)>>,
}
impl ClientAuth {
    pub fn new(secret: StaticSecret, relay: [u8; 32]) -> Self { Self { secret, relay, group: Mutex::new(None) } }
    pub fn public_key(&self) -> [u8; 32] { PublicKey::from(&self.secret).to_bytes() }
}
#[async_trait::async_trait]
impl LinkAuthenticator for ClientAuth {
    async fn server(&self, _: &mut dyn LinkIo, _: [u8; 16], _: u32) -> io::Result<LinkSessionRef> { Err(denied("client authenticator used as server")) }
    async fn client(&self, io: &mut dyn LinkIo, bond: [u8; 16], index: u32) -> io::Result<LinkSessionRef> {
        let (session, nonce) = if index == 0 {
            let shared = shared(&self.secret, self.relay)?;
            let peer = self.public_key();
            io.write_u32(2).await?; io.write_all(&peer).await?; io.flush().await?;
            let mut challenge = [0; 32]; io.read_exact(&mut challenge).await?;
            io.write_all(&tag(shared.as_bytes(), &[AUTH, &challenge, &peer])?).await?; io.flush().await?;
            (Session::new(peer, tag(shared.as_bytes(), &[LINK, &bond, &challenge])?), [0; 32])
        } else {
            let session = self.group.lock().as_ref().filter(|(id, s)| *id == bond && s.active()).map(|(_, s)| s.clone()).ok_or_else(|| denied("client bond is not authenticated"))?;
            let mut challenge = [0; 32]; io.read_exact(&mut challenge).await?;
            io.write_all(&session.proof(&challenge, &bond, index)?).await?; io.flush().await?; (session, challenge)
        };
        let mut confirmation = [0; 32]; io.read_exact(&mut confirmation).await?;
        session.verify_confirmation(&bond, index, &nonce, &confirmation)?;
        if index == 0 { *self.group.lock() = Some((bond, session.clone())); }
        Ok(session)
    }
}

/// Resolve the shared CLI/startup identity path without requiring configuration.
pub fn identity_path(key_file: Option<std::path::PathBuf>) -> std::path::PathBuf {
    resolve_identity_path(key_file, std::env::var_os("FLUXPEER_RELAY_KEY_FILE"), std::env::var_os("FLUXPEER_DATA_DIR"))
}

fn resolve_identity_path(key_file: Option<std::path::PathBuf>, env_key: Option<std::ffi::OsString>, data_dir: Option<std::ffi::OsString>) -> std::path::PathBuf {
    key_file.or_else(|| env_key.map(std::path::PathBuf::from)).unwrap_or_else(|| {
        std::path::PathBuf::from(data_dir.unwrap_or_else(|| "/var/lib/fluxpeer".into())).join("relay.key")
    })
}

/// Read or exclusively create a persisted random identity. Never derive it from
/// the public node_id. Refuse symlinks and permissive files on Unix.
pub fn load_identity(path: &std::path::Path) -> io::Result<StaticSecret> {
    let mut options = std::fs::OpenOptions::new(); options.read(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.custom_flags(libc::O_NOFOLLOW); }
    match options.open(path) {
        Ok(mut file) => {
            #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; if file.metadata()?.permissions().mode() & 0o077 != 0 { return Err(denied("relay identity file must be private (0600)")); } }
            let mut bytes = Zeroizing::new(Vec::new()); Read::by_ref(&mut file).take(65).read_to_end(&mut bytes)?;
            if bytes.len() != 32 { return Err(denied("relay identity file must contain exactly 32 raw bytes")); }
            let mut key = Zeroizing::new([0; 32]); key.copy_from_slice(&bytes); Ok(StaticSecret::from(*key))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                let mut directory = std::fs::DirBuilder::new(); directory.recursive(true);
                #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; directory.mode(0o700); }
                directory.create(parent)?;
            }
            let key = Zeroizing::new(nonce()?);
            let mut options = std::fs::OpenOptions::new(); options.write(true).create_new(true);
            #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
            match options.open(path) {
                Ok(mut file) => { file.write_all(key.as_ref())?; file.sync_all()?; Ok(StaticSecret::from(*key)) },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => load_identity(path),
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

/// Revoke a session even when its protocol task is cancelled during a handshake.
pub struct Lease(pub LinkSessionRef);
impl Drop for Lease { fn drop(&mut self) { self.0.invalidate(); } }

#[cfg(test)]
mod tests;
