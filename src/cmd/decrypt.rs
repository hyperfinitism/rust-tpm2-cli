// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::SymmetricMode;
use tss_esapi::structures::{Auth, InitialValue, MaxBuffer};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;

/// Decrypt data with a symmetric key held by the TPM.
///
/// Reads ciphertext from a file (or stdin) and writes plaintext to the
/// output file (or stdout).
#[derive(Parser)]
pub struct DecryptCmd {
    /// Symmetric key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Authorization value for the key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Cipher mode (cfb, cbc, ecb, ofb, ctr)
    #[arg(short = 'G', long = "mode", default_value = "cfb", value_parser = parse::parse_symmetric_mode)]
    pub mode: SymmetricMode,

    /// Initialization vector input file (default: all zeros)
    #[arg(short = 'i', long = "iv")]
    pub iv_input: Option<PathBuf>,

    /// Output file for the IV produced by the TPM (for chaining)
    #[arg(long = "iv-out")]
    pub iv_output: Option<PathBuf>,

    /// Output file for the decrypted data (default: stdout)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Input file to decrypt (default: stdin)
    #[arg()]
    pub input: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl DecryptCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.key_context)?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(key_handle.into(), auth.clone())
                .context("tr_set_auth failed")?;
        }

        let ciphertext = read_input(&self.input)?;
        let iv_in = read_iv(&self.iv_input)?;

        let data =
            MaxBuffer::try_from(ciphertext).map_err(|e| anyhow::anyhow!("input too large: {e}"))?;

        let session_path = self.session.as_deref();
        let (plaintext, iv_out) = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.encrypt_decrypt_2(key_handle, true, self.mode, data.clone(), iv_in.clone())
        })
        .context("TPM2_EncryptDecrypt2 (decrypt) failed")?;

        if let Some(ref path) = self.output {
            output::write_to_file(path, plaintext.as_bytes())?;
            info!("plaintext written to {}", path.display());
        } else {
            output::write_binary_stdout(plaintext.as_bytes())?;
        }

        if let Some(ref path) = self.iv_output {
            output::write_to_file(path, iv_out.as_bytes())?;
            info!("IV written to {}", path.display());
        }

        Ok(())
    }
}

fn read_input(path: &Option<PathBuf>) -> anyhow::Result<Vec<u8>> {
    match path {
        Some(p) => std::fs::read(p).with_context(|| format!("reading input: {}", p.display())),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading stdin")?;
            Ok(buf)
        }
    }
}

fn read_iv(path: &Option<PathBuf>) -> anyhow::Result<InitialValue> {
    match path {
        Some(p) => {
            let data = std::fs::read(p).with_context(|| format!("reading IV: {}", p.display()))?;
            InitialValue::try_from(data).map_err(|e| anyhow::anyhow!("invalid IV: {e}"))
        }
        None => Ok(InitialValue::default()),
    }
}
