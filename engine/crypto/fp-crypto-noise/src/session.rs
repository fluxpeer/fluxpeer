// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::PacketData;
// use parking_lot::Mutex;
use portable_atomic::{AtomicU64, Ordering};
use rand_core::{OsRng, RngCore};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

/// Maximum nonce value before a rekey is required.
/// Set to 2^48 as a practical safety margin well below the 2^64 theoretical limit.
const MAX_NONCE: u64 = 1 << 48;

/// Maximum random padding bytes added to each packet (0..=15).
const MAX_PADDING: u8 = 15;

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicU64,
    receiving_key_counter: ReceivingKeyCounterValidator,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Session: {}<- ->{}", self.receiving_index, self.sending_index)
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone, Default)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), fp_crypto::Error> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(fp_crypto::Error::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(fp_crypto::Error::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), fp_crypto::Error> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(fp_crypto::Error::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(fp_crypto::Error::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while !i.is_multiple_of(WORD_SIZE) && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(local_index: u32, peer_index: u32, receiving_key: [u8; 32], sending_key: [u8; 32]) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key)
                    .expect("known-safe: 32-byte key is valid for CHACHA20_POLY1305"),
            ),
            sender: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &sending_key)
                    .expect("known-safe: 32-byte key is valid for CHACHA20_POLY1305"),
            ),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: Default::default(),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), fp_crypto::Error> {
        self.receiving_key_counter.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&mut self, counter: u64) -> Result<(), fp_crypto::Error> {
        let ret = self.receiving_key_counter.mark_did_receive(counter);
        if ret.is_ok() {
            self.receiving_key_counter.receive_cnt += 1;
        }
        ret
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the size of the formatted packet, or an error if the nonce is exhausted
    pub(super) fn format_packet_data<'a>(
        &self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], fp_crypto::Error> {
        if dst.len() < src.len() + crate::DATA_OVERHEAD_SZ {
            return Err(fp_crypto::Error::DestinationBufferTooSmall);
        }

        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed);

        // Guard against nonce overflow — require rekey before exhaustion
        if sending_key_counter >= MAX_NONCE {
            return Err(fp_crypto::Error::NonceExhausted);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&crate::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        // Add random padding to prevent traffic-length analysis.
        // Layout of plaintext before encryption: [padding_len: u8] [random_padding: padding_len bytes] [payload]
        let padding_len = (OsRng.next_u32() % (MAX_PADDING as u32 + 1)) as u8;
        let padded_len = 1 + padding_len as usize + src.len();

        // Write padding header: first byte is the padding length
        data[0] = padding_len;
        // Fill random padding bytes
        if padding_len > 0 {
            let mut padding_buf = [0u8; MAX_PADDING as usize];
            OsRng.fill_bytes(&mut padding_buf[..padding_len as usize]);
            data[1..1 + padding_len as usize].copy_from_slice(&padding_buf[..padding_len as usize]);
        }
        // Copy actual payload after padding
        data[1 + padding_len as usize..padded_len].copy_from_slice(src);

        let n: usize = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
            self.sender
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut data[..padded_len],
                )
                .map(|tag| {
                    data[padded_len..padded_len + AEAD_SIZE].copy_from_slice(tag.as_ref());
                    padded_len + AEAD_SIZE
                })
                .map_err(|_| fp_crypto::Error::InvalidAeadTag)?
        };

        Ok(&mut dst[..DATA_OFFSET + n])
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    /// dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub(super) fn receive_packet_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], fp_crypto::Error> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            return Err(fp_crypto::Error::DestinationBufferTooSmall);
        }
        if packet.receiver_idx != self.receiving_index {
            return Err(fp_crypto::Error::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(packet.counter)?;

        let decrypted = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());
            dst[..ct_len].copy_from_slice(packet.encrypted_encapsulated_packet);
            self.receiver
                .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&[]), &mut dst[..ct_len])
                .map_err(|_| fp_crypto::Error::InvalidAeadTag)?
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_counter_mark(packet.counter)?;

        // Strip padding added by the sender.
        // Layout: [padding_len: u8] [random_padding: padding_len bytes] [payload]
        if decrypted.is_empty() {
            return Err(fp_crypto::Error::InvalidPacket);
        }
        let padding_len = decrypted[0] as usize;
        let header_len = 1 + padding_len;
        if header_len > decrypted.len() {
            return Err(fp_crypto::Error::InvalidPacket);
        }
        let payload_len = decrypted.len() - header_len;

        // Shift payload to the beginning of dst so the caller gets a clean slice
        if payload_len > 0 {
            dst.copy_within(header_len..header_len + payload_len, 0);
        }
        Ok(&mut dst[..payload_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(c.will_accept(i), Err(fp_crypto::Error::InvalidCounter)));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(fp_crypto::Error::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
