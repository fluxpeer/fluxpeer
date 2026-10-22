// SPDX-License-Identifier: BSD-3-Clause
//! Parent-owned pipe: no discoverable port or unauthenticated stop endpoint.
use std::io;
#[cfg(test)]
use tokio::io::{AsyncRead, AsyncReadExt};

fn decode(count: usize, byte: &[u8]) -> io::Result<()> {
    match count {
        0 => Ok(()), // Parent disappeared: clean up instead of leaving an orphan.
        1 if byte.first() == Some(&b'S') => Ok(()),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid member stop request")),
    }
}

#[cfg(windows)]
pub(crate) async fn stdin() -> io::Result<()> {
    let (send, receive) = tokio::sync::oneshot::channel();
    // Tokio stdin uses an uncancellable blocking-pool read, which can keep the
    // runtime alive after bootstrap fails. A detached OS thread has no runtime
    // shutdown dependency and owns no network effects or child processes.
    std::thread::Builder::new().name("member-stop".into()).spawn(move || {
        use std::io::Read;
        let mut byte = [0_u8; 1];
        let result = std::io::stdin().read(&mut byte).and_then(|count| decode(count, &byte));
        let _ = send.send(result);
    })?;
    receive.await.map_err(|_| io::Error::other("member stop reader exited without a result"))?
}

#[cfg(test)]
async fn receive(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
    let mut byte = [0_u8; 1];
    decode(reader.read(&mut byte).await?, &byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[tokio::test]
    async fn parent_command_or_pipe_close_stops_bootstrap_but_invalid_input_is_an_error() {
        for (bytes, expected) in [(b"S".as_slice(), true), (b"".as_slice(), true), (b"X".as_slice(), false)] {
            let (mut parent, mut child) = tokio::io::duplex(8);
            parent.write_all(bytes).await.unwrap(); drop(parent);
            assert_eq!(receive(&mut child).await.is_ok(), expected);
        }
        let (_parent, mut child) = tokio::io::duplex(8);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(10), receive(&mut child)).await.is_err());
    }
}
