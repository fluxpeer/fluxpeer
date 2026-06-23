//! Android JNI surface — Kotlin `dev.fluxpeer.fluxpeer.FluxpeerNative` calls
//! these, which forward to the shared `*_impl` cores in the parent module. Only
//! the marshaling differs from the C ABI: `jstring` in/out instead of
//! `*const c_char`, and the transport-event callback upcalls into a Kotlin
//! object (a `VpnService`) rather than invoking a C function pointer.
//!
//! Cross-build: `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o jniLibs
//! build --release` → `libfp_node_client_sys.so` per ABI (see
//! `scripts/build-android.sh`).

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::OnceLock;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jint, jstring};
use jni::{JNIEnv, JavaVM};

use super::Callback;

/// Process-wide JVM handle (constant once attached) used by the C callback
/// trampolines to reach Kotlin from tokio worker threads.
static JVM: OnceLock<JavaVM> = OnceLock::new();

/// The current session's Kotlin event sink (a `FluxpeerNative.EventSink` /
/// VpnService). Replaced on each connect; cleared has no callback.
static EVENT_CB: parking_lot::Mutex<Option<GlobalRef>> = parking_lot::Mutex::new(None);

/// New a Java string, returning a JVM-null on failure (never panics across FFI).
fn jstr(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|o| o.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Read a `JString` param into a Rust `String`; `None` on null/decode error.
fn read_jstring(env: &mut JNIEnv, s: &JString) -> Option<String> {
    if s.is_null() {
        return None;
    }
    env.get_string(s).ok().map(|js| js.into())
}

/// Adopt + free a C string handed to a transport callback (the dispatcher
/// `into_raw`'d it; we own it). Returns its contents.
fn take_cstring(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    let owned = unsafe { CString::from_raw(p as *mut c_char) };
    owned.to_string_lossy().into_owned()
}

/// Upcall into Kotlin: `EventSink.onEvent(connected, data, error)`. Frees the
/// two owned C strings regardless of whether the upcall succeeds.
fn emit(connected: bool, data: *const c_char, error_message: *const c_char) {
    let data = take_cstring(data);
    let error = take_cstring(error_message);

    let Some(vm) = JVM.get() else { return };
    // Attaching a tokio worker thread to the JVM is required before any JNI call.
    let mut env = match vm.attach_current_thread() {
        Ok(guard) => guard,
        Err(e) => {
            tracing::error!("[jni] attach_current_thread failed: {e}");
            return;
        }
    };

    let guard = EVENT_CB.lock();
    let Some(cb) = guard.as_ref() else { return };

    let (Ok(jd), Ok(je)) = (env.new_string(&data), env.new_string(&error)) else {
        return;
    };
    let jd: JObject = jd.into();
    let je: JObject = je.into();
    if let Err(e) = env.call_method(
        cb,
        "onEvent",
        "(ZLjava/lang/String;Ljava/lang/String;)V",
        &[JValue::Bool(connected as u8), JValue::Object(&jd), JValue::Object(&je)],
    ) {
        tracing::error!("[jni] onEvent upcall failed: {e}");
    }
}

extern "C" fn on_connected(data: *const c_char, error_message: *const c_char) {
    emit(true, data, error_message);
}

extern "C" fn on_closed(data: *const c_char, error_message: *const c_char) {
    emit(false, data, error_message);
}

// ---- JNI entry points -----------------------------------------------------

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNative_generateKeypair<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jstring {
    jstr(&mut env, &super::keypair_val().to_string())
}

/// `connectHandshakeOnly(req: String, sink: EventSink?) -> String`. `sink`, if
/// non-null, receives `onEvent(connected, data, error)` upcalls.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNative_connectHandshakeOnly<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    req: JString<'l>,
    sink: JObject<'l>,
) -> jstring {
    let Some(raw) = read_jstring(&mut env, &req) else {
        return jstr(&mut env, &super::err_val("invalid req: null or non-utf8").to_string());
    };

    // Stash the JVM (once) + this session's event sink for the trampolines.
    if let Ok(vm) = env.get_java_vm() {
        let _ = JVM.set(vm);
    }
    let sink_ref = if sink.is_null() {
        None
    } else {
        env.new_global_ref(&sink).ok()
    };
    let has_sink;
    {
        let mut guard = EVENT_CB.lock();
        *guard = sink_ref;
        has_sink = guard.is_some();
    }

    let (on_conn, on_close): (Option<Callback>, Option<Callback>) =
        if has_sink { (Some(on_connected), Some(on_closed)) } else { (None, None) };

    let v = super::connect_handshake_only_impl(&raw, on_conn, on_close);
    jstr(&mut env, &v.to_string())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNative_attachTun<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    fd: jint,
) -> jstring {
    jstr(&mut env, &super::attach_tun_impl(fd).to_string())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNative_disconnect<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
) -> jstring {
    let out = super::disconnect_impl();
    *EVENT_CB.lock() = None;
    jstr(&mut env, &out.to_string())
}

#[cfg(feature = "enroll")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNative_enroll<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    req: JString<'l>,
) -> jstring {
    let Some(raw) = read_jstring(&mut env, &req) else {
        return jstr(&mut env, &super::err_val("invalid req: null or non-utf8").to_string());
    };
    jstr(&mut env, &super::enroll_impl(&raw).to_string())
}

#[cfg(feature = "enroll")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNative_gateway<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    req: JString<'l>,
) -> jstring {
    let Some(raw) = read_jstring(&mut env, &req) else {
        return jstr(&mut env, &super::err_val("invalid req: null or non-utf8").to_string());
    };
    jstr(&mut env, &super::gateway_impl(&raw).to_string())
}
