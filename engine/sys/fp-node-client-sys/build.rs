//! Generate the C header (`fp_node_client_sys.h`) the iOS/Android consumers
//! include. Best-effort: header generation never fails the library build — on
//! any cbindgen error we write a hand-maintained fallback so the symbol surface
//! is always documented. See the `fluxpeer-mobile-ffi-plan` memory.

fn main() {
    println!("cargo:rerun-if-changed=src/ffi/mod.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    let header = "fp_node_client_sys.h";
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());

    // Generate into a buffer and write it ourselves. NB: cbindgen's
    // `Bindings::write_to_file` returns `false` when the on-disk content is
    // unchanged — relying on that bool wrongly triggers the fallback on a
    // no-op rebuild. Inspect the bytes instead.
    let mut buf = Vec::new();
    let generated = cbindgen::Config::from_file("cbindgen.toml")
        .ok()
        .and_then(|config| {
            cbindgen::Builder::new()
                .with_crate(&crate_dir)
                .with_config(config)
                .generate()
                .ok()
        })
        .map(|bindings| bindings.write(&mut buf))
        .is_some();

    // Use cbindgen's output only if it carries the core symbol; otherwise fall
    // back to the hand-maintained header (cbindgen missing / parse hiccup).
    let ok = generated
        && std::str::from_utf8(&buf).map(|s| s.contains("fp_connect_handshake_only")).unwrap_or(false);
    let bytes: &[u8] = if ok { &buf } else { fallback_header().as_bytes() };
    if std::fs::write(header, bytes).is_err() {
        println!("cargo:warning=fp-node-client-sys: failed to write {header}");
    }
}

/// Hand-maintained mirror of the FFI surface (`src/ffi/mod.rs`). Keep in sync.
fn fallback_header() -> &'static str {
    r#"/* fluxpeer mobile node FFI — fallback header (cbindgen unavailable). */
#ifndef FP_NODE_CLIENT_SYS_H
#define FP_NODE_CLIENT_SYS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Generate an x25519 device keypair: {"private_key":"<hex>","public_key":"<hex>"}. */
char *fp_generate_keypair(void);

/* Free a string returned by any fp_* function. */
void fp_free_string(char *p);

/* Phase 1: build transport + run the Noise handshake (no TUN yet).
   on_connected / on_closed may be NULL. */
char *fp_connect_handshake_only(const char *req_json,
                                void (*on_connected)(const char *data, const char *error_message),
                                void (*on_closed)(const char *data, const char *error_message));

/* Phase 2: attach the OS-provided TUN fd; data plane goes live. */
char *fp_attach_tun(int32_t fd);

/* Tear down the tunnel (idempotent). */
char *fp_disconnect(void);

/* Enroll against a control-server; returns the device identity JSON.
   Present only when built with the `enroll` feature (on by default);
   define FP_FEATURE_ENROLL to match the default mobile build. */
#if defined(FP_FEATURE_ENROLL)
char *fp_enroll(const char *req_json);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* FP_NODE_CLIENT_SYS_H */
"#
}
