// SPDX-License-Identifier: BSD-3-Clause
//! Bound shutdown even if an OS DNS lookup cannot be interrupted.
use std::time::Duration;

pub(crate) fn shutdown(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_timeout(Duration::from_millis(500));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocked_resolver_does_not_hold_engine_join() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let (release, waiting) = std::sync::mpsc::channel();
        rt.spawn_blocking(move || { started.send(()).unwrap(); let _ = waiting.recv(); });
        ready.recv().unwrap();
        let start = std::time::Instant::now();
        shutdown(rt);
        release.send(()).unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
