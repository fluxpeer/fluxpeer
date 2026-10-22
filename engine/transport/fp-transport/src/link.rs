// SPDX-License-Identifier: BSD-3-Clause
//! Optional authentication boundary for bonded physical links. Direct WG users
//! may omit it: WG authenticates their packets. Relays must install it because
//! a logical relay session assigns an identity to otherwise opaque frames.
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub trait LinkIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> LinkIo for T {}

pub trait LinkSession: Send + Sync {
    fn peer(&self) -> [u8; 32];
    fn active(&self) -> bool;
    fn invalidate(&self);
}
pub type Session = Arc<dyn LinkSession>;
pub type Authenticator = Arc<dyn LinkAuthenticator>;

#[async_trait::async_trait]
pub trait LinkAuthenticator: Send + Sync {
    async fn client(&self, io: &mut dyn LinkIo, bond: [u8; 16], index: u32) -> std::io::Result<Session>;
    async fn server(&self, io: &mut dyn LinkIo, bond: [u8; 16], index: u32) -> std::io::Result<Session>;
}

pub fn denied(message: &str) -> std::io::Error { std::io::Error::new(std::io::ErrorKind::PermissionDenied, message) }

/// Version 2 carries the physical link index and required authentication mode.
pub async fn write_header(io: &mut (impl LinkIo + ?Sized), bond: &[u8; 16], total: u8, index: usize, authenticated: bool) -> std::io::Result<()> {
    let index = u32::try_from(index).map_err(|_| denied("bond link index exhausted"))?;
    io.write_all(&[2]).await?;
    io.write_all(bond).await?;
    io.write_all(&[total]).await?;
    io.write_all(&index.to_be_bytes()).await?;
    io.write_all(&[u8::from(authenticated)]).await?;
    io.flush().await
}
pub async fn read_header(io: &mut (impl LinkIo + ?Sized), authenticated: bool) -> std::io::Result<([u8; 16], u8, u32)> {
    if io.read_u8().await? != 2 { return Err(denied("unsupported bond protocol version; version 2 required")); }
    let mut bond = [0; 16]; io.read_exact(&mut bond).await?;
    let total = io.read_u8().await?;
    let index = io.read_u32().await?;
    if io.read_u8().await? != u8::from(authenticated) { return Err(denied("bond link authentication mode mismatch")); }
    if !(1..=8).contains(&total) { return Err(denied("invalid bond link count")); }
    Ok((bond, total, index))
}
