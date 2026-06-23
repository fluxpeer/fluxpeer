pub struct Inner {
    pub sender: crate::TransportSender,
    pub closer: tokio::sync::broadcast::Sender<Option<crate::DisconnectReason>>,
    pub close_rx: tokio::sync::broadcast::Receiver<Option<crate::DisconnectReason>>,
}

impl Inner {
    pub async fn send(
        &mut self,
        cryptor: &mut crate::RawCryptor,
        packet: crate::Packet,
        buf: &mut [u8],
    ) -> Result<(), crate::Error> {
        let packet = match &packet {
            crate::Packet::Handshake(_) => return Err(crate::Error::InvalidPacket),
            crate::Packet::Data(data) => crate::Packet::Data(cryptor.on_send(data, buf)?.to_vec()).try_into()?,
            _ => packet.try_into()?,
        };
        // Resolve close-signal state. `Lagged` is not "channel closed" — it
        // just means our receiver fell behind and tokio has already skipped us
        // to the most recent slot. We re-poll to see the real state (Empty /
        // Closed / Ok(reason)). Treating Lagged as fatal close used to kill
        // freshly-handshaked peers within ~260ms (see iPhone 7 / 2026-05-14
        // AnyTLS audit).
        use tokio::sync::broadcast::error::TryRecvError;
        let real_state = match self.close_rx.try_recv() {
            Err(TryRecvError::Lagged(n)) => {
                tracing::warn!("[Peer::Send] close_rx lagged {n}, re-polling for real state");
                self.close_rx.try_recv()
            }
            other => other,
        };
        let error = match real_state {
            Err(TryRecvError::Empty) | Err(TryRecvError::Lagged(_)) => {
                // No close signal pending; proceed with send.
                #[cfg(feature = "debug_log")]
                tracing::info!("[Peer::Send]close_rx empty, continue sending.");
                if let Err(e) = self.sender.send(packet).await {
                    e.into()
                } else {
                    #[cfg(feature = "debug_log")]
                    tracing::info!("[Peer::Send]has been sended.");
                    return Ok(());
                }
            }
            Err(TryRecvError::Closed) => {
                tracing::error!("[Peer::Send]close_rx closed, stop & close peer_inner.");
                crate::Error::TransportError("sender has been closed".to_string())
            }
            Ok(_) => {
                tracing::error!("[Peer::Send]close_rx received, stop & close peer_inner.");
                crate::Error::TransportError("sender has been closed".to_string())
            }
        };

        tracing::error!(
            "[Peer:Send]{}:sender has been closed, remove peer inner",
            hex::encode(cryptor.get_peer_public()?)
        );
        self.close(Some(error.clone().into())).await;
        Err(error)
    }

    pub async fn close(&mut self, reason: Option<crate::DisconnectReason>) {
        let packet = if let Some(reason) = reason.clone()
            && let Ok(packet) = Into::<crate::Packet>::into(reason).try_into()
        {
            packet
        } else {
            vec![]
        };

        let _ = self.sender.send(packet).await;
        self.sender.close().await;
        let _ = self.closer.send(reason);
        tracing::warn!("peer inner closed")
    }
}
