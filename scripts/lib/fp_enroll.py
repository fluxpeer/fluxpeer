#!/usr/bin/env python3
"""fp_enroll.py — enroll a device on a fluxpeer control-server via the PoP flow.

The control-server's enroll is a two-round proof-of-possession (audit #11): wg keys
are x25519 (DH), not signing keys, so the client proves it holds the private half by
running an ECDH challenge:

  1. POST /api/v1/enroll/challenge {wg_public_key}      -> {challenge_id, server_pub}
  2. proof = X25519(wg_priv, server_pub)                (the raw shared secret, hex)
  3. POST /api/v1/enroll {invite_code, name, wg_public_key, challenge_id, proof}
                                                        -> {id, auth_token, address_v4, ...}

X25519 is implemented inline (pure-python RFC 7748) so this has zero pip deps and
matches x25519-dalek exactly (clamped scalar). Used by scripts/e2e-android-node.sh
to enroll a real device key (e.g. a phone's wg key) without the device UI.

  fp_enroll.py <ctrl_url> <invite_code> <name> <wg_priv_hex> [wg_pub_hex]
prints the enrolled device JSON to stdout.
"""
import sys, json, urllib.request, urllib.error

P = 2**255 - 19


def _clamp(k):
    k = bytearray(k); k[0] &= 248; k[31] &= 127; k[31] |= 64; return bytes(k)


def x25519(k_bytes, u_bytes):
    """RFC 7748 X25519 (clamped) — matches x25519-dalek."""
    k = int.from_bytes(_clamp(k_bytes), "little")
    u = bytearray(u_bytes); u[31] &= 127; u = int.from_bytes(u, "little")
    x1, x2, z2, x3, z3, swap, a24 = u, 1, 0, u, 1, 0, 121665
    for t in range(254, -1, -1):
        kt = (k >> t) & 1; swap ^= kt
        if swap:
            x2, x3 = x3, x2; z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % P; AA = A * A % P
        B = (x2 - z2) % P; BB = B * B % P
        E = (AA - BB) % P
        C = (x3 + z3) % P; D = (x3 - z3) % P
        DA = D * A % P; CB = C * B % P
        x3 = pow((DA + CB) % P, 2, P)
        z3 = x1 * pow((DA - CB) % P, 2, P) % P
        x2 = AA * BB % P
        z2 = E * (AA + a24 * E) % P
        if swap:
            x2, x3 = x3, x2; z2, z3 = z3, z2
        swap = 0
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def pubkey(priv_hex):
    return x25519(bytes.fromhex(priv_hex), (9).to_bytes(32, "little")).hex()


def _post(ctrl, path, obj):
    req = urllib.request.Request(ctrl + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=10).read())
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code}: {e.read().decode()[:300]}\n"); sys.exit(1)


def enroll(ctrl, code, name, priv_hex, pub_hex=None):
    pub_hex = pub_hex or pubkey(priv_hex)
    derived = pubkey(priv_hex)
    if derived != pub_hex:
        sys.stderr.write(f"WARN: derived pub {derived} != claimed {pub_hex}\n")
    ch = _post(ctrl, "/api/v1/enroll/challenge", {"wg_public_key": pub_hex})
    proof = x25519(bytes.fromhex(priv_hex), bytes.fromhex(ch["server_pub"])).hex()
    return _post(ctrl, "/api/v1/enroll", {
        "invite_code": code, "name": name, "wg_public_key": pub_hex,
        "challenge_id": ch["challenge_id"], "proof": proof,
    })


if __name__ == "__main__":
    if len(sys.argv) < 5:
        sys.stderr.write(__doc__); sys.exit(2)
    ctrl, code, name, priv = sys.argv[1:5]
    pub = sys.argv[5] if len(sys.argv) > 5 else None
    print(json.dumps(enroll(ctrl, code, name, priv, pub)))
