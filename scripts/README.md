# scripts

- **regression-netns.sh** — single-host fluxpeer regression. Runs a real 2-node mesh
  (second node in a network namespace + veth, so traffic traverses the wg tunnel)
  and asserts enroll/handshake/TUN, 0%-loss bidirectional ping with direct-path
  latency+ttl, real bidirectional transfer, and REVOKE-1. Needs root + a built
  `fluxpeer`. `FLUXPEER_BIN=… scripts/regression-netns.sh` (exit 0 = all pass).
