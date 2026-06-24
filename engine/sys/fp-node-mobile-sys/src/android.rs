//! Android JNI surface — Kotlin `dev.fluxpeer.fluxpeer.FluxpeerNode` calls
//! `runNode(cfgJson, tunFd)` / `stopNode()`. The engine upcalls the Kotlin static
//! `protectSocket(int fd): boolean` so `VpnService.protect` excludes each egress
//! socket from the VPN (else our own wg packets loop back into the tun).

use std::ffi::{CString, c_char, c_void};
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::OnceLock;

use jni::objects::{GlobalRef, JClass, JString, JValue};
use jni::sys::{JNI_VERSION_1_6, jint, jstring};
use jni::{JNIEnv, JavaVM};
use parking_lot::Mutex;

// Android logging (liblog). `tracing_subscriber::fmt` writes to stdout, which an app's
// stdout is discarded (routed to /dev/null) on Android — so engine logs would be
// invisible. Route them to logcat via __android_log_write instead (tag `fluxpeer-node`).
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
}
const ANDROID_LOG_INFO: i32 = 4;

/// A `tracing_subscriber` writer that forwards each formatted line to logcat.
struct LogcatWriter;
impl std::io::Write for LogcatWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Trim the trailing newline tracing adds; logcat frames lines itself.
        let trimmed = buf.strip_suffix(b"\n").unwrap_or(buf);
        if let Ok(msg) = CString::new(trimmed) {
            // SAFETY: both pointers are valid NUL-terminated C strings for this call.
            unsafe { __android_log_write(ANDROID_LOG_INFO, c"fluxpeer-node".as_ptr(), msg.as_ptr()) };
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Process-wide JVM handle, cached at load so worker threads can attach for the
/// `protectSocket` upcall.
static JVM: OnceLock<JavaVM> = OnceLock::new();
/// A GlobalRef to the `FluxpeerNode` class — cached from `runNode`'s env (a thread
/// that can resolve the app class), so the worker-thread protect callback can call
/// the static method without `find_class` (which fails off the main classloader).
static NODE_CLASS: OnceLock<GlobalRef> = OnceLock::new();
/// Stop signal for the running engine (oneshot fires → `run_embedded` is cancelled).
static STOP: Mutex<Option<tokio::sync::oneshot::Sender<()>>> = Mutex::new(None);

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> jint {
    // Best-effort: route engine `tracing` to logcat for on-device diagnosis.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(|| LogcatWriter)
        .try_init();
    let _ = JVM.set(vm);
    JNI_VERSION_1_6
}

fn jstr(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|o| o.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// Engine → Kotlin upcall: `FluxpeerNode.protectSocket(fd)` (VpnService.protect).
/// Runs on a tokio worker thread, so it must attach to the JVM first.
fn protect_socket(fd: RawFd) {
    let (Some(vm), Some(class)) = (JVM.get(), NODE_CLASS.get()) else {
        tracing::warn!(fd, "protect_socket: JVM/class not ready");
        return;
    };
    let mut env = match vm.attach_current_thread() {
        Ok(e) => e,
        Err(e) => {
            tracing::error!("[jni] attach_current_thread failed: {e}");
            return;
        }
    };
    match env.call_static_method(class, "protectSocket", "(I)Z", &[JValue::Int(fd as jint)]) {
        Ok(_) => tracing::info!(fd, "protected egress socket via VpnService"),
        Err(e) => tracing::error!(fd, "[jni] protectSocket upcall failed: {e}"),
    }
}

/// `runNode(cfgJson: String, tunFd: int) -> String`. Starts the full node engine on
/// a background thread with its own multi-thread runtime, adopting `tunFd`. Returns
/// a JSON status immediately (the engine runs until `stopNode` or error).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNode_runNode<'l>(
    mut env: JNIEnv<'l>,
    class: JClass<'l>,
    cfg_json: JString<'l>,
    tun_fd: jint,
) -> jstring {
    // Cache the class so the worker-thread protect callback can reach Kotlin.
    if NODE_CLASS.get().is_none()
        && let Ok(g) = env.new_global_ref(&class)
    {
        let _ = NODE_CLASS.set(g);
    }
    let cfg: String = match env.get_string(&cfg_json) {
        Ok(s) => s.into(),
        Err(_) => return jstr(&mut env, "{\"error\":\"cfg_json null or non-utf8\"}"),
    };
    let fd = tun_fd as RawFd;

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    *STOP.lock() = Some(stop_tx);

    let spawned = std::thread::Builder::new().name("fp-node".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("[fp-node] tokio runtime build failed: {e}");
                return;
            }
        };
        rt.block_on(async move {
            let protect: fluxpeer_node::ProtectFn = Arc::new(protect_socket);
            tokio::select! {
                r = fluxpeer_node::run_embedded(&cfg, fd, Some(protect)) => {
                    tracing::warn!(?r, "[fp-node] engine exited");
                }
                _ = stop_rx => tracing::info!("[fp-node] stop requested"),
            }
        });
    });

    match spawned {
        Ok(_) => jstr(&mut env, "{\"ok\":true}"),
        Err(e) => jstr(&mut env, &format!("{{\"error\":\"spawn failed: {e}\"}}")),
    }
}

/// `stopNode()`. Signals the engine to shut down.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_fluxpeer_fluxpeer_FluxpeerNode_stopNode<'l>(
    _env: JNIEnv<'l>,
    _class: JClass<'l>,
) {
    if let Some(tx) = STOP.lock().take() {
        let _ = tx.send(());
    }
}
