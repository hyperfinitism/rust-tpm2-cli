// SPDX-License-Identifier: Apache-2.0
//! Shared test infrastructure for tpm2-cli integration tests.
//!
//! Provides `SwtpmSession` which manages an swtpm instance and provides
//! pre-configured `assert_cmd::Command` builders via the `-T` flag.

#![allow(dead_code)]

use assert_cmd::Command;
use socket2::{Domain, SockAddr, Socket, Type};
use std::io::Write;
use std::net::TcpStream;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tss_esapi::structures::Public;
use tss_esapi::traits::Marshall;

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

    /// Create a primary object from an explicitly constructed public template.
    pub fn create_primary_from_public(&self, name: &str, public: &Public) -> std::path::PathBuf {
        let template = self.write_public_template(&format!("{name}.template"), public);
        let context = self.tmp.path().join(format!("{name}.ctx"));
        self.cmd("createprimary")
            .arg("--template")
            .arg(template)
            .arg("--context")
            .arg(&context)
            .assert()
            .success();
        context
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

    /// Create the EK and AK files required by credential activation commands.
    pub fn create_credential_keys(
        &self,
    ) -> (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let ek_context = self.tmp.path().join("ek.ctx");
        let ek_public = self.tmp.path().join("ek.pub");
        self.cmd("createek")
            .args(["-G", "rsa", "-c"])
            .arg(&ek_context)
            .arg("-u")
            .arg(&ek_public)
            .assert()
            .success();

        self.flush_transient();

        let ak_context = self.tmp.path().join("ak.ctx");
        let ak_public = self.tmp.path().join("ak.pub");
        let ak_private = self.tmp.path().join("ak.priv");
        let ak_name = self.tmp.path().join("ak.name");
        self.cmd("createak")
            .arg("-C")
            .arg(Self::file_ref(&ek_context))
            .arg("-c")
            .arg(&ak_context)
            .args(["-G", "rsa", "-g", "sha256", "-u"])
            .arg(&ak_public)
            .arg("-r")
            .arg(&ak_private)
            .arg("-n")
            .arg(&ak_name)
            .assert()
            .success();

        (ek_context, ek_public, ak_context, ak_name)
    }

    /// Create and load a child object from an explicitly constructed public template.
    pub fn create_and_load_from_public(
        &self,
        parent_ctx: &std::path::Path,
        name: &str,
        public: &Public,
        sensitive_data: Option<&[u8]>,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let template = self.write_public_template(&format!("{name}.template"), public);
        let priv_path = self.tmp.path().join(format!("{name}.priv"));
        let pub_path = self.tmp.path().join(format!("{name}.pub"));
        let ctx_path = self.tmp.path().join(format!("{name}.ctx"));

        let mut create = self.cmd("create");
        create
            .arg("-C")
            .arg(Self::file_ref(parent_ctx))
            .arg("--template")
            .arg(template)
            .arg("-r")
            .arg(&priv_path)
            .arg("-u")
            .arg(&pub_path);
        if let Some(data) = sensitive_data {
            let path = self.write_tmp_file(&format!("{name}.sensitive"), data);
            create.arg("--seal-data").arg(path);
        }
        create.assert().success();

        self.cmd("load")
            .arg("-C")
            .arg(Self::file_ref(parent_ctx))
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

    /// Create an object and policy session authorizing duplication to one parent.
    pub fn create_object_for_duplication(
        &self,
        original_parent: &std::path::Path,
        new_parent: &std::path::Path,
        name: &str,
    ) -> (
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let parent_name = self.read_object_name(new_parent, &format!("{name}.parent-name"));
        let empty_name = self.write_tmp_file(&format!("{name}.empty-name"), &[]);
        let trial = self.tmp.path().join(format!("{name}.trial.ctx"));
        let policy = self.tmp.path().join(format!("{name}.policy"));
        self.cmd("startauthsession")
            .arg("-S")
            .arg(&trial)
            .assert()
            .success();
        self.cmd("policyduplicationselect")
            .arg("-S")
            .arg(&trial)
            .arg("-n")
            .arg(&empty_name)
            .arg("-N")
            .arg(&parent_name)
            .arg("-L")
            .arg(&policy)
            .assert()
            .success();
        let policy = tss_esapi::structures::Digest::try_from(self.read_file(&policy))
            .expect("invalid duplication policy digest");
        let (object, public, _) = self.create_and_load_from_public(
            original_parent,
            name,
            &duplicable_ecc_public_with_auth_policy(policy),
            None,
        );
        let object_name = self.read_object_name(&object, &format!("{name}.object-name"));

        let session = self.tmp.path().join(format!("{name}.policy.ctx"));
        self.cmd("startauthsession")
            .args(["--policy-session", "-S"])
            .arg(&session)
            .assert()
            .success();
        self.cmd("policyduplicationselect")
            .arg("-S")
            .arg(&session)
            .arg("-n")
            .arg(&object_name)
            .arg("-N")
            .arg(&parent_name)
            .assert()
            .success();

        (object, public, object_name, session)
    }

    /// Write a marshalled public template for a command accepting `--template`.
    pub fn write_public_template(&self, name: &str, public: &Public) -> std::path::PathBuf {
        let bytes = public
            .marshall()
            .expect("failed to marshal public template");
        self.write_tmp_file(name, &bytes)
    }

    /// Read an object's TPM name through the CLI and store its binary representation.
    pub fn read_object_name(
        &self,
        object_context: &std::path::Path,
        name: &str,
    ) -> std::path::PathBuf {
        let assertion = self
            .cmd("readpublic")
            .arg("-c")
            .arg(Self::file_ref(object_context))
            .assert()
            .success();
        let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);
        let name_hex = stdout
            .lines()
            .find_map(|line| line.strip_prefix("name: 0x"))
            .expect("readpublic output did not contain the object name");
        let value = hex::decode(name_hex).expect("readpublic returned a non-hex object name");
        self.write_tmp_file(name, &value)
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

pub fn unrestricted_rsa_decryption_public() -> Public {
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::structures::RsaExponent;
    use tss_esapi::utils::create_unrestricted_encryption_decryption_rsa_public;

    create_unrestricted_encryption_decryption_rsa_public(
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .expect("failed to build unrestricted RSA decryption public area")
}

pub fn ecdh_public() -> Public {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    };
    use tss_esapi::structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder,
    };

    let parameters = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .expect("failed to build ECDH parameters");
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(false)
        .build()
        .expect("failed to build ECDH attributes");
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .expect("failed to build ECDH public area")
}

pub fn symmetric_cipher_public() -> Public {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
    use tss_esapi::structures::{
        Digest, PublicBuilder, SymmetricCipherParameters, SymmetricDefinitionObject,
    };

    let attributes = ObjectAttributesBuilder::new()
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .build()
        .expect("failed to build symmetric key attributes");
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .expect("failed to build symmetric cipher public area")
}

pub fn ecdaa_public() -> Public {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    };
    use tss_esapi::structures::{
        EcDaaScheme, EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder,
    };

    let parameters = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDaa(EcDaaScheme::new(
            HashingAlgorithm::Sha256,
            0,
        )))
        .with_curve(EccCurve::BnP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .expect("failed to build ECDAA parameters");
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .expect("failed to build ECDAA attributes");
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .expect("failed to build ECDAA public area")
}

pub fn ecc_signing_public_with_admin_policy(policy: tss_esapi::structures::Digest) -> Public {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    };
    use tss_esapi::structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder,
    };

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_admin_with_policy(true)
        .with_sign_encrypt(true)
        .build()
        .expect("failed to build policy-authorized ECC signing attributes");
    let parameters = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .expect("failed to build policy-authorized ECC signing parameters");

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(policy)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .expect("failed to build policy-authorized ECC signing public area")
}

pub fn x509_signing_public() -> Public {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
        key_bits::RsaKeyBits,
    };
    use tss_esapi::structures::{
        PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    };

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .with_x509_sign(true)
        .build()
        .expect("failed to build X.509 signing attributes");
    let parameters = PublicRsaParametersBuilder::new()
        .with_scheme(
            RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .expect("failed to build X.509 signing scheme"),
        )
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .build()
        .expect("failed to build X.509 signing parameters");
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_parameters(parameters)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("failed to build X.509 signing public area")
}

pub fn duplicable_ecc_public_with_auth_policy(policy: tss_esapi::structures::Digest) -> Public {
    duplicable_ecc_public_with_policy(Some(policy))
}

fn duplicable_ecc_public_with_policy(policy: Option<tss_esapi::structures::Digest>) -> Public {
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    };
    use tss_esapi::structures::{
        EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder, PublicEccParametersBuilder,
    };

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .expect("failed to build duplicable object attributes");
    let parameters = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .expect("failed to build duplicable ECC parameters");
    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default());
    if let Some(policy) = policy {
        builder = builder.with_auth_policy(policy);
    }
    builder
        .build()
        .expect("failed to build duplicable ECC public area")
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
