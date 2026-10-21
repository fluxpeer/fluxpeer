//! Enroll proof-of-possession (PoP).
//!
//! Enroll is invite-gated, but nothing stopped a caller from enrolling a wg public
//! key it does NOT own — squatting another device's key (IPAM grab + downstream
//! poisoning), audit #11. wg keys are x25519 (DH), not signing keys, so the client
//! can't just sign a challenge. Instead we run a two-round ECDH challenge:
//!
//!  1. client → `POST /enroll/challenge {wg_public_key: P}`; server mints an
//!     ephemeral x25519 keypair `(e_priv, e_pub)`, remembers `(e_priv, P)` under a
//!     random `challenge_id` (60s TTL), and returns `{challenge_id, server_pub:e_pub}`.
//!  2. client computes `shared = DH(wg_priv, e_pub)` and sends it as `proof`.
//!  3. server recomputes `DH(e_priv, P)` and compares. They're equal iff the client
//!     holds the private half of `P` — proof of possession. Challenge is single-use.
//!
//! State is in-memory (a self-host runs one control-server); a multi-instance
//! deployment behind a load balancer would need shared/sticky challenge storage.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use fp_crypto::x25519::{PublicKey, StaticSecret};
use parking_lot::Mutex;

/// A challenge is one online round-trip; keep it short-lived.
const CHALLENGE_TTL: Duration = Duration::from_secs(60);
/// Cap outstanding challenges so a flood of `/enroll/challenge` can't grow the map
/// unboundedly (each is pruned on TTL, but bound the worst case too).
const MAX_PENDING: usize = 4096;

struct Pending {
    /// Server's ephemeral private key for this challenge.
    ephemeral: StaticSecret,
    /// The wg public key the client claims to own (binds the proof to this key).
    claimed_pub: [u8; 32],
    expires: Instant,
}

fn pending() -> &'static Mutex<HashMap<String, Pending>> {
    static PENDING: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn prune(map: &mut HashMap<String, Pending>, now: Instant) {
    map.retain(|_, p| p.expires > now);
}

/// Result of [`new_challenge`]: hand back to the client to drive round 2.
pub(crate) struct Challenge {
    pub(crate) challenge_id: String,
    /// Server ephemeral public key, hex.
    pub(crate) server_pub: String,
}

/// Mint a challenge for a client claiming `claimed_pub_hex`. Returns `None` if the
/// claimed key isn't a valid 32-byte hex/base64 key or the pending table is full.
pub(crate) fn new_challenge(claimed_pub_hex: &str) -> Option<Challenge> {
    let claimed = fluxpeer_sdk::key::decode(claimed_pub_hex)?;
    let ephemeral = StaticSecret::from(random_32());
    if !ephemeral.diffie_hellman(&PublicKey::from(claimed)).was_contributory() {
        return None;
    }
    let server_pub = hex::encode(PublicKey::from(&ephemeral).to_bytes());
    let challenge_id = crate::auth::random_hex(16);
    let now = Instant::now();
    let mut map = pending().lock();
    prune(&mut map, now);
    if map.len() >= MAX_PENDING {
        return None;
    }
    map.insert(
        challenge_id.clone(),
        Pending {
            ephemeral,
            claimed_pub: claimed,
            expires: now + CHALLENGE_TTL,
        },
    );
    Some(Challenge { challenge_id, server_pub })
}

/// Verify a round-2 proof. Consumes the challenge (single-use). True iff the client
/// proved possession of the private key for `claimed_pub_hex`.
pub(crate) fn verify(challenge_id: &str, claimed_pub_hex: &str, proof_hex: &str) -> bool {
    let now = Instant::now();
    let entry = {
        let mut map = pending().lock();
        prune(&mut map, now);
        map.remove(challenge_id) // single-use: gone whether or not it verifies
    };
    let Some(entry) = entry else {
        return false;
    };
    if entry.expires <= now {
        return false;
    }
    // The proof must be for the SAME key the challenge was minted for.
    let Some(claimed) = fluxpeer_sdk::key::decode(claimed_pub_hex) else {
        return false;
    };
    if claimed != entry.claimed_pub {
        return false;
    }
    let Some(proof) = decode_key(proof_hex) else {
        return false;
    };
    // expected = DH(e_priv, P); the client sent DH(wg_priv, e_pub) — equal iff it
    // holds wg_priv for P.
    let expected = entry.ephemeral.diffie_hellman(&PublicKey::from(entry.claimed_pub));
    expected.was_contributory() && ct_eq(expected.as_bytes(), &proof)
}

fn random_32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    b
}

fn decode_key(hex_str: &str) -> Option<[u8; 32]> {
    let v = hex::decode(hex_str).ok()?;
    v.try_into().ok()
}

/// Constant-time 32-byte compare.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> (StaticSecret, String) {
        let sk = StaticSecret::from([seed; 32]);
        (sk.clone(), hex::encode(PublicKey::from(&sk).to_bytes()))
    }

    fn low_order_keys() -> Vec<[u8; 32]> {
        let mut keys = vec![[0; 32]];
        let mut one = [0; 32]; one[0] = 1; keys.push(one);
        // p-1, p and p+1: order-two / non-canonical aliases of zero and one.
        for first in [0xec, 0xed, 0xee] {
            let mut key = [0xff; 32]; key[0] = first; key[31] = 0x7f; keys.push(key);
        }
        for encoded in [
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        ] { keys.push(decode_key(encoded).unwrap()); }
        // X25519 masks bit 255; all high-bit aliases must be rejected too.
        let aliases: Vec<_> = keys.iter().map(|key| { let mut key = *key; key[31] |= 0x80; key }).collect();
        keys.extend(aliases);
        keys
    }

    #[test]
    fn low_order_keys_are_rejected_before_challenge_and_at_verification() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        for key in low_order_keys() {
            for encoded in [hex::encode(key), STANDARD.encode(key)] {
                assert!(new_challenge(&encoded).is_none());
                // Defense in depth: even a previously minted pending challenge
                // must not accept the publicly computable all-zero DH result.
                let id = crate::auth::random_hex(16);
                pending().lock().insert(id.clone(), Pending {
                    ephemeral: StaticSecret::from([17; 32]), claimed_pub: key,
                    expires: Instant::now() + CHALLENGE_TTL,
                });
                assert!(!verify(&id, &encoded, &"00".repeat(32)));
                assert!(!pending().lock().contains_key(&id));
            }
        }
    }

    #[test]
    fn honest_client_proves_possession() {
        let (sk, pub_hex) = keypair(7);
        let chal = new_challenge(&pub_hex).expect("challenge");
        let server_pub: [u8; 32] = decode_key(&chal.server_pub).unwrap();
        let proof = hex::encode(sk.diffie_hellman(&PublicKey::from(server_pub)).to_bytes());
        assert!(verify(&chal.challenge_id, &pub_hex, &proof));
    }

    #[test]
    fn attacker_without_private_key_fails() {
        // Victim's public key; attacker holds a DIFFERENT private key.
        let (_victim_sk, victim_pub) = keypair(7);
        let (attacker_sk, _attacker_pub) = keypair(9);
        let chal = new_challenge(&victim_pub).expect("challenge");
        let server_pub: [u8; 32] = decode_key(&chal.server_pub).unwrap();
        // Attacker can only DH with its own key → wrong shared secret.
        let forged = hex::encode(attacker_sk.diffie_hellman(&PublicKey::from(server_pub)).to_bytes());
        assert!(!verify(&chal.challenge_id, &victim_pub, &forged));
    }

    #[test]
    fn challenge_is_single_use() {
        let (sk, pub_hex) = keypair(7);
        let chal = new_challenge(&pub_hex).expect("challenge");
        let server_pub: [u8; 32] = decode_key(&chal.server_pub).unwrap();
        let proof = hex::encode(sk.diffie_hellman(&PublicKey::from(server_pub)).to_bytes());
        assert!(verify(&chal.challenge_id, &pub_hex, &proof));
        // Second use of the same challenge is rejected (consumed).
        assert!(!verify(&chal.challenge_id, &pub_hex, &proof));
    }

    #[test]
    fn unknown_challenge_rejected() {
        let (_sk, pub_hex) = keypair(7);
        assert!(!verify("deadbeef", &pub_hex, &"00".repeat(32)));
    }
}
