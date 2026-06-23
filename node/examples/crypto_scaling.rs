//! Measures wg AEAD (ChaCha20-Poly1305) encrypt throughput scaling across cores —
//! the operation that caps the data plane (Phase-1 stress test: tcp-direct ≈ 1.5
//! Gbit/s, the single-core ceiling). The node shards peers across N worker tasks, so
//! aggregate throughput scales with this curve. Each thread drives its own
//! independent wg session (one peer's worker), exactly like the sharded node.
//!
//! cargo run --release --example crypto_scaling # on the target box
//!
//! Reads `BENCH_PACKETS` (default 3,000,000) and `BENCH_WORKERS` (default
//! "1,2,4,8,16") from the env.

use std::time::Instant;

use fp_crypto::RawCryptor;
use fp_crypto::x25519::{PublicKey, StaticSecret};

fn rand32() -> [u8; 32] {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .expect("read /dev/urandom");
    b
}

/// An established initiator session ready to `on_send` (full handshake done).
fn make_session() -> RawCryptor {
    let a_priv = StaticSecret::from(rand32());
    let b_priv = StaticSecret::from(rand32());
    let b_pub = PublicKey::from(&b_priv);
    let mut a = RawCryptor::new::<fp_crypto_noise::Cryptor>();
    let mut b = RawCryptor::new::<fp_crypto_noise::Cryptor>();
    let init = a.init_handshake(a_priv, b_pub).expect("init");
    let resp = b.handle_handshake(b_priv, b_pub, &init).expect("handle").expect("resp");
    a.handle_handshake_response(&resp).expect("resp install");
    a
}

/// Encrypt `packets` MTU-sized frames on one session; return bytes produced.
fn bench_one(packets: u64) -> u64 {
    let mut c = make_session();
    let pkt = vec![7u8; 1400];
    let mut dst = vec![0u8; 1600];
    let mut bytes = 0u64;
    for _ in 0..packets {
        if let Ok(out) = c.on_send(&pkt, &mut dst) {
            bytes += out.len() as u64;
        }
    }
    bytes
}

fn main() {
    let packets: u64 = std::env::var("BENCH_PACKETS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3_000_000);
    let workers: Vec<usize> = std::env::var("BENCH_WORKERS")
        .unwrap_or_else(|_| "1,2,4,8,16".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    println!(
        "wg encrypt scaling — {packets} pkts × 1400 B per worker ({} hw threads)",
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
    );
    let mut base = 0.0;
    for &w in &workers {
        let t = Instant::now();
        let handles: Vec<_> = (0..w).map(|_| std::thread::spawn(move || bench_one(packets))).collect();
        let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        let secs = t.elapsed().as_secs_f64();
        let gbit = (total as f64 * 8.0) / 1e9 / secs;
        if w == 1 {
            base = gbit;
        }
        let speedup = if base > 0.0 { gbit / base } else { 1.0 };
        println!("  workers={w:2}   {gbit:6.2} Gbit/s   {speedup:4.1}×   ({secs:.2}s)");
    }
}
