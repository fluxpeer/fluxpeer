// SPDX-License-Identifier: BSD-3-Clause
//! C ABI for the full node. Callback strings are borrowed only during the call.
use std::{ffi::{CStr, CString, c_char}, io, os::fd::{BorrowedFd, IntoRawFd}, sync::Arc};
use parking_lot::Mutex;
use serde_json::{Value, json};
type Event = extern "C" fn(u64, u32, *const c_char) -> i32;
struct Engine { generation: u64, stop: tokio::sync::oneshot::Sender<()>, thread: std::thread::JoinHandle<()> }
static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);
fn output(value: io::Result<Value>) -> *mut c_char {
    let value = match value { Ok(value) => json!({"code":200,"result":value}), Err(error) => json!({"code":201,"message":error.to_string()}) };
    CString::new(value.to_string()).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}
unsafe fn input<'a>(value: *const c_char) -> io::Result<&'a str> {
    if value.is_null() { return Err(io::Error::other("null request")); }
    // SAFETY: callers guarantee a live NUL-terminated request for this call.
    unsafe { CStr::from_ptr(value) }.to_str().map_err(io::Error::other)
}
fn event(callback: Event, generation: u64, kind: u32, value: &str) -> io::Result<()> {
    let value = CString::new(value).map_err(io::Error::other)?;
    if callback(generation, kind, value.as_ptr()) != 0 { return Err(io::Error::other("platform rejected engine event")); }
    Ok(())
}
/// # Safety
/// value must be null or a pointer returned by this module, freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_mobile_free(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: ownership of this module's CString is returned by the caller.
        drop(unsafe { CString::from_raw(value) });
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn fp_mobile_keypair() -> *mut c_char {
    output(fluxpeer_node::mobile::keypair())
}
/// # Safety
/// request must be a live NUL-terminated UTF-8 string for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_mobile_enroll(request: *const c_char) -> *mut c_char {
    output((|| {
        // SAFETY: forwarded from this function's caller contract.
        let request = unsafe { input(request) }?;
        let value: Value = serde_json::from_str(request).map_err(io::Error::other)?;
        let field = |name| value.get(name).and_then(Value::as_str).filter(|v| !v.is_empty()).ok_or_else(|| io::Error::other("missing enrollment field"));
        let rt = tokio::runtime::Runtime::new()?;
        let result = rt.block_on(fluxpeer_node::mobile::enroll(field("token")?, field("name")?, field("wg_private_key")?));
        crate::runtime::shutdown(rt); result
    })())
}
/// # Safety
/// config must be a live NUL-terminated UTF-8 string; fd must remain valid during
/// this call. The engine duplicates it. callback must remain valid until stop.
/// Callbacks must not synchronously call stop (it joins the calling thread).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fp_mobile_start(config: *const c_char, fd: i32, generation: u64, callback: Option<Event>) -> *mut c_char {
    output((|| {
        // SAFETY: the caller owns these arguments for the entire call.
        let config = unsafe { input(config) }?.to_string();
        let _: Value = serde_json::from_str(&config).map_err(io::Error::other)?;
        let callback = callback.ok_or_else(|| io::Error::other("missing callback"))?;
        if fd < 0 { return Err(io::Error::other("invalid packet fd")); }
        let mut slot = ENGINE.lock();
        if slot.is_some() { return Err(io::Error::other("previous engine must be stopped first")); }
        // SAFETY: fd is borrowed from the caller, never adopted or closed here.
        let fd = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
        let (stop, receive) = tokio::sync::oneshot::channel();
        let thread = std::thread::Builder::new().name("fp-ios-node".into()).spawn(move || {
            let result = (|| -> io::Result<()> {
                let rt = tokio::runtime::Runtime::new()?;
                let routes = Arc::new(move |json: &str| {
                    event(callback, generation, 1, json)?;
                    event(callback, generation, 2, "{}")
                });
                let result = rt.block_on(async move {
                    let engine = async move { fluxpeer_node::run_embedded_with_routes(&config, fd.into_raw_fd(), None, Some(routes)).await };
                    tokio::select! { result = engine => Some(result), _ = receive => None }
                });
                crate::runtime::shutdown(rt);
                match result { None => Ok(()), Some(result) => Err(result.err().unwrap_or_else(|| io::Error::other("engine exited"))) }
            })();
            if let Err(error) = result { let _ = event(callback, generation, 3, &json!({"error":error.to_string()}).to_string()); }
        })?;
        *slot = Some(Engine { generation, stop, thread }); Ok(json!({"ok":true}))
    })())
}
#[unsafe(no_mangle)]
pub extern "C" fn fp_mobile_stop(generation: u64) -> *mut c_char {
    output((|| {
        let mut slot = ENGINE.lock();
        if slot.as_ref().is_some_and(|engine| engine.generation != generation) { return Err(io::Error::other("stale engine generation")); }
        if let Some(engine) = slot.take() { let _ = engine.stop.send(()); engine.thread.join().map_err(|_| io::Error::other("engine thread failed"))?; }
        Ok(json!({"ok":true}))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    type Observed = (u64, u32, String);
    static EVENTS: Mutex<Option<std::sync::mpsc::Sender<Observed>>> = Mutex::new(None);
    extern "C" fn accept(generation: u64, kind: u32, value: *const c_char) -> i32 {
        // SAFETY: the ABI supplies a live callback string for this call.
        let value = unsafe { CStr::from_ptr(value) }.to_str().unwrap().to_string();
        if let Some(send) = EVENTS.lock().as_ref() { send.send((generation, kind, value)).unwrap(); }
        0
    }
    #[test]
    fn fd_is_borrowed_and_stale_generation_cannot_stop_replacement() {
        use std::os::fd::AsRawFd;
        let (fd, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let config = c"{}";
        let (send, receive) = std::sync::mpsc::channel(); *EVENTS.lock() = Some(send);
        // SAFETY: live string and socket, static callback; returned strings freed once.
        unsafe {
            let started = fp_mobile_start(config.as_ptr(), fd.as_raw_fd(), 42, Some(accept));
            assert!(CStr::from_ptr(started).to_str().unwrap().contains("200")); fp_mobile_free(started);
            let (generation, kind, payload) = receive.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            assert_eq!((generation, kind), (42, 3)); // Invalid bootstrap exits, never ready.
            assert!(serde_json::from_str::<Value>(&payload).unwrap()["error"].is_string());
            let stale = fp_mobile_stop(41); assert!(CStr::from_ptr(stale).to_str().unwrap().contains("201")); fp_mobile_free(stale);
            let stopped = fp_mobile_stop(42); assert!(CStr::from_ptr(stopped).to_str().unwrap().contains("200")); fp_mobile_free(stopped);
        }
        assert!(receive.try_recv().is_err()); *EVENTS.lock() = None;
        assert!(fd.local_addr().is_ok());
    }
}
