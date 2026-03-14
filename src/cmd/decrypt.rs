// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{InitialValue, MaxBuffer};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::{self, parse_hex_u32};
use crate::session::execute_with_optional_session;

/// Decrypt data with a symmetric key held by the TPM.
///
/// Reads ciphertext from a file (or stdin) and writes plaintext to the
/// output file (or stdout).
#[derive(Parser)]
pub struct DecryptCmd {
    /// Symmetric key context file path
    #[arg(
        short = 'c',
        long = "key-context",
        conflicts_with = "key_context_handle"
    )]
    pub key_context: Option<PathBuf>,

    /// Symmetric key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "key-context-handle", value_parser = parse_hex_u32, conflicts_with = "key_context")]
    pub key_context_handle: Option<u32>,

    /// Authorization value for the key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Cipher mode (cfb, cbc, ecb, ofb, ctr)
    #[arg(short = 'G', long = "mode", default_value = "cfb")]
    pub mode: String,

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
    fn context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.key_context, self.key_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --key-context or --key-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context_source()?)?;
        let mode = parse::parse_symmetric_mode(&self.mode)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(key_handle.into(), auth)
                .context("tr_set_auth failed")?;
        }

        let ciphertext = read_input(&self.input)?;
        let iv_in = read_iv(&self.iv_input)?;

        let data =
            MaxBuffer::try_from(ciphertext).map_err(|e| anyhow::anyhow!("input too large: {e}"))?;

        let session_path = self.session.as_deref();
        let (plaintext, iv_out) = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.encrypt_decrypt_2(key_handle, true, mode, data.clone(), iv_in.clone())
        })
        .context("TPM2_EncryptDecrypt2 (decrypt) failed")?;

        if let Some(ref path) = self.output {
            output::write_to_file(path, plaintext.value())?;
            info!("plaintext written to {}", path.display());
        } else {
            output::write_binary_stdout(plaintext.value())?;
        }

        if let Some(ref path) = self.iv_output {
            output::write_to_file(path, iv_out.value())?;
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
