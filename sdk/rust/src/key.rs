// SPDX-License-Identifier: BSD-3-Clause
//! Canonical control-plane public keys: 32 bytes, encoded as lowercase hex.

use base64::{Engine, engine::general_purpose::STANDARD};

/// Decode hexadecimal or WireGuard standard base64 without panicking.
pub fn decode(value: &str) -> Option<[u8; 32]> {
    let bytes = if value.len() == 64 {
        hex::decode(value).ok()?
    } else {
        STANDARD.decode(value).ok()?
    };
    bytes.try_into().ok()
}

/// Normalize an accepted key to the storage/wire representation.
pub fn normalize(value: &str) -> Option<String> {
    decode(value).map(hex::encode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_encodings_and_invalid_lengths() {
        let bytes = [0xab; 32];
        let canonical = hex::encode(bytes);
        for value in [canonical.clone(), canonical.to_uppercase(), STANDARD.encode(bytes)] {
            assert_eq!(decode(&value), Some(bytes));
            assert_eq!(normalize(&value), Some(canonical.clone()));
        }
        for value in ["".to_owned(), "gg".repeat(32), "ff".repeat(31), STANDARD.encode([1; 33])] {
            assert_eq!(decode(&value), None);
        }
    }
}
