// SPDX-License-Identifier: BSD-3-Clause
#![cfg(test)]
use std::{path::Path, process::{Child, Command, Stdio}, time::{Duration, Instant}};
use fluxpeer_relay_server::auth::{load_identity, ServerAuth};

fn command(data: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fluxpeer"));
    cmd.arg("relay").env_remove("FLUXPEER_RELAY_KEY_FILE")
        .env("FLUXPEER_DATA_DIR", data).env("RUST_LOG", "info")
        .env("FLUXPEER_RELAY_ADDR", "127.0.0.1:0")
        .env("FLUXPEER_RELAY_STUN_ADDR", "127.0.0.1:0")
        .env_remove("FLUXPEER_RELAY_ANYTLS_ADDR").env_remove("FLUXPEER_RELAY_BOND_ADDR");
    cmd
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}
fn start(data: &Path, log: &Path) -> Running {
    let output = std::fs::File::create(log).unwrap();
    let mut child = Running(command(data).stdout(output.try_clone().unwrap()).stderr(output).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let logs = std::fs::read_to_string(log).unwrap();
        assert!(child.0.try_wait().unwrap().is_none(), "relay exited: {logs}");
        if logs.contains("relay-server (plain TCP) listening") { return child; }
        assert!(Instant::now() < deadline, "relay startup timed out: {logs}");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn public_key(mut cmd: Command) -> String {
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.len(), 65);
    assert!(text.trim_end().bytes().all(|b| b.is_ascii_hexdigit()));
    text
}
fn server_public(path: &Path) -> String {
    let public = ServerAuth::new(load_identity(path).unwrap()).public_key();
    public.iter().map(|byte| format!("{byte:02x}")).collect::<String>() + "\n"
}
#[test]
fn default_startup_public_key_and_restart_share_private_identity() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("new/state");
    let key = data.join("relay.key");
    let first = start(&data, &temp.path().join("first.log"));
    let bytes = std::fs::read(&key).unwrap();
    assert_eq!(bytes.len(), 32);
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&data).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(data.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    }
    let mut cmd = command(&data); cmd.arg("public-key");
    assert_eq!(public_key(cmd), server_public(&key));
    drop(first);
    let _second = start(&data, &temp.path().join("second.log"));
    assert_eq!(std::fs::read(&key).unwrap(), bytes);
}
#[test]
fn public_key_creates_identity_and_respects_overrides() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("state");
    let mut cmd = command(&data); cmd.arg("public-key");
    assert_eq!(public_key(cmd), server_public(&data.join("relay.key")));
    let env_key = temp.path().join("env/relay.key");
    let mut cmd = command(&data); cmd.arg("public-key").env("FLUXPEER_RELAY_KEY_FILE", &env_key);
    let expected = public_key(cmd);
    assert_eq!(expected, server_public(&env_key));
    let cli_key = temp.path().join("cli/relay.key");
    let mut cmd = command(&data);
    cmd.args(["public-key", "--key-file"]).arg(&cli_key).env("FLUXPEER_RELAY_KEY_FILE", &env_key);
    assert_eq!(public_key(cmd), server_public(&cli_key));
    assert_eq!(expected, server_public(&env_key));
}
#[cfg(unix)]
#[test]
fn public_key_refuses_unsafe_existing_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let key = temp.path().join("relay.key");
    load_identity(&key).unwrap();
    let link = temp.path().join("link.key"); symlink(&key, &link).unwrap();
    for path in [&link, &key] {
        if path == &key { std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap(); }
        let out = command(temp.path()).args(["public-key", "--key-file"]).arg(path).stderr(Stdio::null()).output().unwrap();
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
}
