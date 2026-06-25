# Mobile end-to-end (Android) — real-node architecture

## TL;DR
The phone runs the **full fluxpeer node engine** (`fp-node-mobile-sys`: magicsock +
disco). It is just a **NAT'd `fluxpeer node`** and peers with a **real `fluxpeer node`**
gateway over the same node↔node path that `scripts/e2e-wan.sh` exercises (udp-direct
hole-punch, relay fallback). There is **no dispatcher gateway** anymore.

`fp-node-server-sys` / `examples/mobilegw` (the old "dispatcher gateway server") is
**RETIRED (2026-06-25)** — it speaks a Noise dispatcher protocol that is NOT
compatible with the phone's disco/magicsock packets (the phone's disco datagrams carry
the `b"fpd1"` `DISCO_MAGIC`; feeding them to the dispatcher's Noise parser yields
`unmatch packet_type`). Do not use it for mobile tests.

## Why this matters (the 2026-06-25 regression)
A mobile e2e that had worked stopped working after
`feat(mobile): run the full node engine on Android` migrated the phone from the old
dispatcher client to the full node engine — but the test topology still used the
retired `mobilegw` dispatcher server. Client and server were speaking different
protocols. Root cause was a **client/server version + protocol skew**, not a code bug.

## 铁律 — aligned local builds for regression
**The client APK and the server/node binaries MUST be built from the same HEAD, locally,
before a regression run.** Build everything on the dev box (one commit, one toolchain),
ship only binaries to test hosts (deploy rule unchanged: never put source on a node).

```bash
git rev-parse --short HEAD                  # pin the commit; tree must be clean
# server/node (musl static, via zig — no cross-gcc needed):
cargo zigbuild --release --target x86_64-unknown-linux-musl -p fluxpeer
# client (Android engine + APK), same HEAD:
ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/<ver> scripts/build-android.sh
( cd ../fluxpeer-app && flutter build apk --debug )
```

## 铁律 — mobile test = UNINSTALL → REBUILD → FRESH INSTALL (never `install -r`)
Every mobile (Android/iOS) test run **must uninstall the app, rebuild the APK, and do a
clean install** — never `adb install -r`, never reuse a stale APK or a stale VPN session.

```bash
adb uninstall dev.fluxpeer.fluxpeer            # delete: clears stale WorkManager DB + VPN state
( cd ../fluxpeer-app && flutter build apk --debug )   # recompile from the pinned HEAD
adb install ../fluxpeer-app/build/app/outputs/flutter-apk/app-debug.apk   # fresh install
# then: join in-app → connect ONCE → wait 1–3 min for disco to converge → test. DO NOT churn.
```
Why: (1) `install -r` keeps the old `androidx.work` WorkDatabase → the new build crashes on
launch. (2) Reconnecting/toggling a live session repeatedly corrupts the VPN tun-fd / NAT
mapping / disco endpoints — the data plane then carries handshakes/keepalives but drops app
traffic (verified: ICMP round-trips at the peer, but the phone never receives the reply).
A clean reinstall is the only reliable reset; **connect once and leave it alone** while disco
converges. Restarting the engine more than necessary makes it worse, not better.

> **Release build caveat:** `flutter build apk --release` currently has an unresolved
> data-plane bug (handshake OK, app traffic doesn't traverse the tunnel) that the R8/JNI keep
> rules + tun-fd lifetime fix did NOT fully resolve — the residual difference looks like
> Flutter release/AOT packaging affecting the native data plane. **Use `--debug` until that
> is fixed.**

## Topology
```
  phone (fp-node-mobile-sys, full node, behind NAT)
        │  enroll → control ; disco/magicsock → gateway (udp-direct or relay)
        ▼
  vd2 (public):  control(:8090) + relay/STUN(:3478) + `fluxpeer node` gateway(:41822)
                 the gateway advertises its public ip:port → control hands it to the
                 phone as its gateway peer (select_gateway: first active peer w/ endpoint)
```

## Enroll (per-device PoP)
Enroll requires proof-of-possession (audit #11): the client proves it holds the wg
private key via an ECDH challenge. `scripts/lib/fp_enroll.py` does this with a pure-python
X25519 (zero deps, matches x25519-dalek) so a test can enroll a known key without the
device UI. A node config (and the app's stored network) must carry the resulting
`auth_token` — the per-device bearer the IDOR fix requires for `/devices/:id/*`.

## Run the e2e
```bash
# server side automated, phone verified over adb (connect the app during the wait window):
scripts/e2e-android-node.sh \
  --gw-host <ssh-host-public> --gw-pub <public-ip:41822> \
  [--phone-priv <hex> --phone-pub <hex>]   # optional: PoP-enroll the phone's key directly
```
Pass: `handshake complete via="udp-direct"`, `ping 0% packet loss`, HTTP-over-mesh `200`.

## Gotchas (operational)
- `pkill -x fluxpeer` also kills `control`/`relay` (same process name) — kill by PID or a
  specific pattern. `pkill -f mobilegw`-style `-f` matches your own ssh command line → 255.
- `ssh` inside a piped loop eats stdin — use `ssh -n`.
- Editing the app's stored config: `adb shell` strips quotes from `sed` patterns and
  SELinux denies `>` into app-private files — feed the command via stdin to
  `run-as <pkg> sh` and use `sed -i`.
