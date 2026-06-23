//! Send-side UDP GSO (generic segmentation offload). Hand the kernel ONE buffer
//! of K equal-size wg datagrams plus a `UDP_SEGMENT` cmsg and it splits them into
//! K packets in a single `sendmsg`. Bulk udp-direct transfers produce equal-size
//! (full-MTU) wg DATA packets, so this collapses ~K `sendto` syscalls into one —
//! closing most of the udp-direct↔tcp-direct gap, which was per-packet syscall
//! overhead (tcp-direct already rides kernel TCP GSO).
//!
//! Linux only; elsewhere — and where the kernel rejects `UDP_SEGMENT` (old
//! kernels) — the batch is flushed one datagram at a time (same wire result, no
//! batching win). GSO requires every segment to be `seg` bytes except the last,
//! which is exactly how a run of full-MTU packets + a short tail looks.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// < 64 KiB: a GSO super-buffer is one pre-segmentation IP datagram.
const MAX_BATCH_BYTES: usize = 60 * 1024;

/// Accumulates equal-size datagrams for ONE destination, flushed as a single GSO
/// `sendmsg`. A differing dst/size, a short (final) segment, or a full batch
/// flushes first.
pub(crate) struct GsoBatch {
    buf: Vec<u8>,
    seg: usize,
    dst: Option<SocketAddr>,
    count: usize,
    /// Cleared once the kernel rejects `UDP_SEGMENT`, so we stop trying it.
    gso_ok: bool,
    /// `FP_NOGSO=1` → never batch (send each datagram immediately); for A/B.
    disabled: bool,
}

impl GsoBatch {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::with_capacity(MAX_BATCH_BYTES),
            seg: 0,
            dst: None,
            count: 0,
            gso_ok: true,
            disabled: std::env::var("FP_NOGSO").is_ok_and(|v| v == "1"),
        }
    }

    /// Queue an encrypted datagram for `dst`, flushing the current batch first if
    /// it can't be extended (different dst, size change, or full).
    pub(crate) async fn push(&mut self, udp: &UdpSocket, dst: SocketAddr, pkt: &[u8]) {
        if self.disabled {
            let _ = udp.send_to(pkt, dst).await;
            return;
        }
        if self.dst != Some(dst)
            || (self.count > 0 && pkt.len() != self.seg)
            || self.buf.len() + pkt.len() > MAX_BATCH_BYTES
        {
            self.flush(udp).await;
        }
        if self.count == 0 {
            self.seg = pkt.len();
            self.dst = Some(dst);
        }
        self.buf.extend_from_slice(pkt);
        self.count += 1;
        // A segment shorter than `seg` can only be the LAST one — flush the run.
        if pkt.len() < self.seg {
            self.flush(udp).await;
        }
    }

    /// Send the accumulated batch and reset. GSO on Linux (one syscall for K
    /// datagrams); a single datagram or the fallback path uses plain `send_to`.
    pub(crate) async fn flush(&mut self, udp: &UdpSocket) {
        if self.count == 0 {
            return;
        }
        let dst = self.dst.take().unwrap();
        if self.count == 1 {
            let _ = udp.send_to(&self.buf, dst).await;
        } else if self.gso_ok && send_segmented(udp, &self.buf, self.seg, dst).await {
            // sent via GSO
        } else {
            self.gso_ok = false; // kernel rejected GSO once → stop trying
            send_split(udp, &self.buf, self.seg, dst).await;
        }
        self.buf.clear();
        self.seg = 0;
        self.count = 0;
    }
}

/// Send `buf` as `ceil(buf/seg)` datagrams in one `sendmsg` via `UDP_SEGMENT`.
/// Returns `false` if the kernel rejected GSO (caller falls back).
#[cfg(target_os = "linux")]
async fn send_segmented(udp: &UdpSocket, buf: &[u8], seg: usize, dst: SocketAddr) -> bool {
    use std::os::fd::AsRawFd;
    // Stable kernel constant; libc doesn't expose it for every target.
    const UDP_SEGMENT: libc::c_int = 103;

    let sa = socket2::SockAddr::from(dst);
    let fd = udp.as_raw_fd();
    loop {
        if udp.writable().await.is_err() {
            return true; // socket gone; don't double-send via fallback
        }
        let r = udp.try_io(tokio::io::Interest::WRITABLE, || {
            let mut iov = libc::iovec {
                iov_base: buf.as_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut cbuf = [0u8; 64]; // > CMSG_SPACE(size_of::<u16>())
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = sa.as_ptr() as *mut libc::c_void;
            msg.msg_namelen = sa.len();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as _;
            // SAFETY: msg_control/controllen set above; we write exactly one cmsg.
            unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::IPPROTO_UDP;
                (*cmsg).cmsg_type = UDP_SEGMENT;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut u16, seg as u16);
                let n = libc::sendmsg(fd, &msg, libc::MSG_DONTWAIT);
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        });
        match r {
            Ok(()) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return false, // EINVAL etc → fall back to per-datagram
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn send_segmented(_udp: &UdpSocket, _buf: &[u8], _seg: usize, _dst: SocketAddr) -> bool {
    false
}

/// Fallback: send the batch one `seg`-sized datagram at a time.
async fn send_split(udp: &UdpSocket, buf: &[u8], seg: usize, dst: SocketAddr) {
    for chunk in buf.chunks(seg.max(1)) {
        let _ = udp.send_to(chunk, dst).await;
    }
}

// ── Receive side: batched recvmmsg ───────────────────────────────────────────
//
// The single udp-reader aggregates EVERY peer's inbound, so reading N datagrams
// per syscall is the receive-side complement to send GSO — without it a 1-core
// receiver's per-packet recv_from caps throughput regardless of how fast the
// sender pushes.

const RECV_BATCH: usize = 32;
const RECV_BUFSZ: usize = 2048;

/// A reusable batch of receive slots. `recv` fills it via `recvmmsg` (Linux) or a
/// single `recv_from` (elsewhere / `FP_NOGSO=1`); `get` reads each datagram.
pub(crate) struct RecvBatch {
    bufs: Box<[[u8; RECV_BUFSZ]]>,
    lens: Box<[usize]>,
    froms: Box<[SocketAddr]>,
    disabled: bool,
}

impl RecvBatch {
    pub(crate) fn new() -> Self {
        let dummy = SocketAddr::from(([0, 0, 0, 0], 0));
        Self {
            bufs: vec![[0u8; RECV_BUFSZ]; RECV_BATCH].into_boxed_slice(),
            lens: vec![0usize; RECV_BATCH].into_boxed_slice(),
            froms: vec![dummy; RECV_BATCH].into_boxed_slice(),
            disabled: std::env::var("FP_NOGSO").is_ok_and(|v| v == "1"),
        }
    }

    /// The `i`-th received datagram: its bytes + source address.
    pub(crate) fn get(&self, i: usize) -> (&[u8], SocketAddr) {
        (&self.bufs[i][..self.lens[i]], self.froms[i])
    }

    /// Receive a batch; returns how many datagrams were read.
    pub(crate) async fn recv(&mut self, udp: &UdpSocket) -> std::io::Result<usize> {
        if self.disabled || cfg!(not(target_os = "linux")) {
            let (len, from) = udp.recv_from(&mut self.bufs[0]).await?;
            self.lens[0] = len;
            self.froms[0] = from;
            return Ok(1);
        }
        #[cfg(target_os = "linux")]
        {
            self.recvmmsg(udp).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            unreachable!()
        }
    }

    #[cfg(target_os = "linux")]
    async fn recvmmsg(&mut self, udp: &UdpSocket) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        let fd = udp.as_raw_fd();
        let n = self.bufs.len();
        loop {
            udp.readable().await?;
            let mut addrs: Vec<libc::sockaddr_storage> = vec![unsafe { std::mem::zeroed() }; n];
            let r = udp.try_io(tokio::io::Interest::READABLE, || {
                let mut iovecs: Vec<libc::iovec> = (0..n)
                    .map(|i| libc::iovec {
                        iov_base: self.bufs[i].as_mut_ptr().cast(),
                        iov_len: RECV_BUFSZ,
                    })
                    .collect();
                let mut msgs: Vec<libc::mmsghdr> = (0..n)
                    .map(|i| {
                        let mut h: libc::mmsghdr = unsafe { std::mem::zeroed() };
                        h.msg_hdr.msg_iov = unsafe { iovecs.as_mut_ptr().add(i) };
                        h.msg_hdr.msg_iovlen = 1;
                        h.msg_hdr.msg_name = unsafe { addrs.as_mut_ptr().add(i).cast() };
                        h.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
                        h
                    })
                    .collect();
                let got = unsafe {
                    libc::recvmmsg(
                        fd,
                        msgs.as_mut_ptr(),
                        n as u32,
                        libc::MSG_DONTWAIT as _,
                        std::ptr::null_mut::<libc::timespec>(),
                    )
                };
                if got < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                for (slot, msg) in self.lens.iter_mut().zip(msgs.iter()).take(got as usize) {
                    *slot = msg.msg_len as usize;
                }
                Ok(got as usize)
            });
            match r {
                Ok(count) => {
                    for (slot, addr) in self.froms.iter_mut().zip(addrs.iter()).take(count) {
                        if let Some(s) = sockaddr_to_socket(addr) {
                            *slot = s;
                        }
                    }
                    return Ok(count);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Convert a kernel `sockaddr_storage` (filled by recvmmsg) to a `SocketAddr`.
#[cfg(target_os = "linux")]
fn sockaddr_to_socket(sa: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match sa.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: family is AF_INET → the storage is a sockaddr_in.
            let a = unsafe { &*(sa as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin_port)))
        }
        libc::AF_INET6 => {
            // SAFETY: family is AF_INET6 → the storage is a sockaddr_in6.
            let a = unsafe { &*(sa as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin6_port)))
        }
        _ => None,
    }
}
