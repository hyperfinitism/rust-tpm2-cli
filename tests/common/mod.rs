// SPDX-License-Identifier: Apache-2.0
//! Shared test infrastructure for tpm2-cli integration tests.
//!
//! Provides `SwtpmSession` which manages an swtpm instance and provides
//! pre-configured `assert_cmd::Command` builders via the `-T` flag.

#![allow(dead_code)]

use assert_cmd::Command;
use assert_fs::TempDir;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::Write;
use std::net::TcpStream;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

/// Maximum number of swtpm startup attempts before giving up.
const MAX_SWTPM_RETRIES: usize = 5;

/// Global port counter to avoid collisions between concurrent tests.
/// Starts at a high ephemeral port and increments by 2 (data + ctrl).
static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

/// Transport mode for swtpm connections.
enum SwtpmTransport {
    /// Unix domain socket with socket path.
    UnixSocket(std::path::PathBuf),
    /// TCP with port number.
    Tcp(u16),
}

/// An active swtpm session with a temporary directory for file state.
///
/// On drop, the swtpm process is killed and the temp directory is cleaned up.
pub struct SwtpmSession {
    _process: Child,
    transport: SwtpmTransport,
    tmp: TempDir,
}

impl SwtpmSession {
    /// Start a new swtpm instance using a Unix domain socket.
    pub fn new() -> Self {
        Self::new_uds()
    }
    /// Start a new swtpm instance using a Unix domain socket.
    ///
    /// UDS avoids TCP port conflicts entirely, making it more reliable for
    /// parallel test execution.
    pub fn new_uds() -> Self {
        for attempt in 0..MAX_SWTPM_RETRIES {
            let tmp = TempDir::new().expect("failed to create temp dir");
            let sock_path = tmp.path().join("swtpm.sock");
            let ctrl_path = tmp.path().join("swtpm.sock.ctrl");

            let mut process = std::process::Command::new("swtpm")
                .args([
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    &format!("dir={}", tmp.path().display()),
                    "--server",
                    &format!("type=unixio,path={}", sock_path.display()),
                    "--ctrl",
                    &format!("type=unixio,path={}", ctrl_path.display()),
                    "--flags",
                    "startup-clear",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to start swtpm");

            // Wait for swtpm to be ready by checking the socket.
            let mut connected = false;
            for _ in 0..40 {
                if let Ok(addr) = SockAddr::unix(&sock_path)
                    && let Ok(sock) = Socket::new(Domain::UNIX, Type::STREAM, None)
                    && sock.connect(&addr).is_ok()
                {
                    connected = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }

            if !connected {
                let _ = process.kill();
                let _ = process.wait();
                if attempt + 1 < MAX_SWTPM_RETRIES {
                    continue;
                }
                panic!(
                    "swtpm failed to start after \
                     {MAX_SWTPM_RETRIES} attempts"
                );
            }

            let session = Self {
                _process: process,
                transport: SwtpmTransport::UnixSocket(sock_path),
                tmp,
            };

            let result = session.cmd("startup").arg("--clear").ok();
            if result.is_err() {
                drop(session);
                if attempt + 1 < MAX_SWTPM_RETRIES {
                    continue;
                }
                panic!(
                    "tpm2 startup --clear failed after \
                     {MAX_SWTPM_RETRIES} attempts"
                );
            }

            return session;
        }
        unreachable!()
    }

    /// Start a new swtpm instance over TCP.
    ///
    /// Retries with different ports if the initial attempt fails due to
    /// port conflicts from parallel test execution.
    pub fn new_tcp() -> Self {
        for attempt in 0..MAX_SWTPM_RETRIES {
            let tmp = TempDir::new().expect("failed to create temp dir");
            let port = pick_port();
            let ctrl_port = port + 1;

            let mut process = std::process::Command::new("swtpm")
                .args([
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    &format!("dir={}", tmp.path().display()),
                    "--server",
                    &format!("type=tcp,port={port}"),
                    "--ctrl",
                    &format!("type=tcp,port={ctrl_port}"),
                    "--flags",
                    "startup-clear",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("failed to start swtpm");

            // Wait for swtpm to be ready.
            let mut connected = false;
            for _ in 0..40 {
                if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
                    connected = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }

            if !connected {
                // swtpm didn't start — likely port conflict. Kill and retry.
                let _ = process.kill();
                let _ = process.wait();
                if attempt + 1 < MAX_SWTPM_RETRIES {
                    continue;
                }
                panic!(
                    "swtpm (tcp) failed to start after {MAX_SWTPM_RETRIES} \
                     attempts (last port: {port})"
                );
            }

            let session = Self {
                _process: process,
                transport: SwtpmTransport::Tcp(port),
                tmp,
            };

            // Run startup --clear.
            let result = session.cmd("startup").arg("--clear").ok();
            if result.is_err() {
                // startup failed — kill swtpm and retry.
                drop(session);
                if attempt + 1 < MAX_SWTPM_RETRIES {
                    continue;
                }
                panic!(
                    "tpm2 startup --clear (tcp) failed after \
                     {MAX_SWTPM_RETRIES} attempts"
                );
            }

            return session;
        }
        unreachable!()
    }

    /// Return the TCTI connection string for this session.
    pub fn tcti(&self) -> String {
        match &self.transport {
            SwtpmTransport::UnixSocket(path) => {
                format!("swtpm:path={}", path.display())
            }
            SwtpmTransport::Tcp(port) => format!("swtpm:host=localhost,port={port}"),
        }
    }

    /// Create a `Command` for a tpm2 subcommand, pre-configured with `-T` and `-v Off`.
    pub fn cmd(&self, subcommand: &str) -> Command {
        let mut cmd = Command::cargo_bin("tpm2").expect("binary not found");
        cmd.arg("-v").arg("Off");
        cmd.arg("-T").arg(self.tcti());
        cmd.arg(subcommand);
        cmd
    }

    /// Access the temp directory for creating test files.
    pub fn tmp(&self) -> &TempDir {
        &self.tmp
    }

    /// Flush all transient objects.
    pub fn flush_transient(&self) {
        let _ = self.cmd("flushcontext").arg("--transient-object").ok();
    }

    /// Flush all loaded sessions.
    pub fn flush_sessions(&self) {
        let _ = self.cmd("flushcontext").arg("--loaded-session").ok();
    }

    /// Helper: create an RSA primary key under owner hierarchy.
    /// Returns the path to the context file.
    pub fn create_primary_rsa(&self, name: &str) -> std::path::PathBuf {
        let ctx = self.tmp.path().join(format!("{name}.ctx"));
        self.cmd("createprimary")
            .args(["-C", "o", "-G", "rsa", "-g", "sha256", "-c"])
            .arg(&ctx)
            .assert()
            .success();
        ctx
    }

    /// Helper: create an ECC primary key under owner hierarchy.
    pub fn create_primary_ecc(&self, name: &str) -> std::path::PathBuf {
        let ctx = self.tmp.path().join(format!("{name}.ctx"));
        self.cmd("createprimary")
            .args(["-C", "o", "-G", "ecc", "-g", "sha256", "-c"])
            .arg(&ctx)
            .assert()
            .success();
        ctx
    }

    /// Helper: create a child signing key and load it.
    /// Returns (ctx_path, pub_path, priv_path).
    pub fn create_and_load_signing_key(
        &self,
        parent_ctx: &std::path::Path,
        alg: &str,
        name: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let priv_path = self.tmp.path().join(format!("{name}.priv"));
        let pub_path = self.tmp.path().join(format!("{name}.pub"));
        let ctx_path = self.tmp.path().join(format!("{name}.ctx"));

        self.cmd("create")
            .arg("-C")
            .arg(format!("file:{}", parent_ctx.display()))
            .args(["-G", alg, "-g", "sha256", "-r"])
            .arg(&priv_path)
            .arg("-u")
            .arg(&pub_path)
            .assert()
            .success();

        self.cmd("load")
            .arg("-C")
            .arg(format!("file:{}", parent_ctx.display()))
            .arg("-r")
            .arg(&priv_path)
            .arg("-u")
            .arg(&pub_path)
            .arg("-c")
            .arg(&ctx_path)
            .assert()
            .success();

        (ctx_path, pub_path, priv_path)
    }

    /// Helper: write binary data to a file in the temp directory.
    pub fn write_tmp_file(&self, name: &str, data: &[u8]) -> std::path::PathBuf {
        let path = self.tmp.path().join(name);
        std::fs::write(&path, data).expect("failed to write tmp file");
        path
    }

    /// Helper: read binary data from a file.
    pub fn read_file(&self, path: &std::path::Path) -> Vec<u8> {
        std::fs::read(path).expect("failed to read file")
    }

    /// Helper: context string for a file path (prepends "file:").
    pub fn file_ref(path: &std::path::Path) -> String {
        format!("file:{}", path.display())
    }

    /// Helper: corrupt a file by overwriting 4 bytes at a given offset.
    pub fn corrupt_file(
        &self,
        src: &std::path::Path,
        dest_name: &str,
        offset: u64,
    ) -> std::path::PathBuf {
        let dest = self.tmp.path().join(dest_name);
        std::fs::copy(src, &dest).expect("failed to copy file");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&dest)
            .expect("failed to open for corruption");
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(offset)).unwrap();
        f.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
        dest
    }
}

impl Drop for SwtpmSession {
    fn drop(&mut self) {
        let _ = self._process.kill();
        let _ = self._process.wait();
    }
}

/// Pick a port pair (data, ctrl = data+1) unlikely to collide.
///
/// Uses a process-wide atomic counter seeded from the PID to spread
/// port ranges across parallel test processes. Each call reserves 2
/// consecutive ports. Falls back to OS-assigned ports if the counter
/// range is exhausted.
fn pick_port() -> u16 {
    // Seed the counter on first use from PID to avoid collisions
    // between parallel cargo-test processes.
    let prev = NEXT_PORT.load(Ordering::Relaxed);
    if prev == 0 {
        let pid = std::process::id() as u16;
        // Map into [20000, 50000) range with stride based on PID.
        let seed = 20000 + (pid.wrapping_mul(37) % 15000) * 2;
        // CAS: only one thread wins the init.
        let _ = NEXT_PORT.compare_exchange(0, seed, Ordering::SeqCst, Ordering::Relaxed);
    }

    loop {
        let port = NEXT_PORT.fetch_add(2, Ordering::SeqCst);
        // Wrap around if we exceed the ephemeral range.
        if !(10000..=60000).contains(&port) {
            NEXT_PORT.store(20000, Ordering::SeqCst);
            continue;
        }
        return port;
    }
}
