// SPDX-License-Identifier: Apache-2.0

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

/// Symmetric encryption or decryption using a TPM-loaded key.
///
/// Wraps TPM2_EncryptDecrypt2. Use `-d` for decryption, omit for encryption.
#[derive(Parser)]
pub struct EncryptDecryptCmd {
    /// Key context file path
    #[arg(
        short = 'c',
        long = "key-context",
        conflicts_with = "key_context_handle"
    )]
    pub key_context: Option<PathBuf>,

    /// Key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "key-context-handle", value_parser = parse_hex_u32, conflicts_with = "key_context")]
    pub key_context_handle: Option<u32>,

    /// Auth value for the key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Decrypt mode (default: encrypt)
    #[arg(short = 'd', long = "decrypt")]
    pub decrypt: bool,

    /// Cipher mode (cfb, cbc, ecb, ofb, ctr, null)
    #[arg(short = 'G', long = "mode", default_value = "null")]
    pub mode: String,

    /// Initial value / IV input file
    #[arg(short = 'i', long = "iv")]
    pub iv: Option<PathBuf>,

    /// Output file for the processed data
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Output file for the IV out
    #[arg(long = "iv-out")]
    pub iv_out: Option<PathBuf>,

    /// Input data file
    #[arg()]
    pub input: PathBuf,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl EncryptDecryptCmd {
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

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let in_data =
            MaxBuffer::try_from(data).map_err(|e| anyhow::anyhow!("input too large: {e}"))?;

        let iv_in = match &self.iv {
            Some(path) => {
                let iv_data = std::fs::read(path)
                    .with_context(|| format!("reading IV from {}", path.display()))?;
                InitialValue::try_from(iv_data).map_err(|e| anyhow::anyhow!("invalid IV: {e}"))?
            }
            None => InitialValue::default(),
        };

        let session_path = self.session.as_deref();
        let (out_data, iv_out) = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.encrypt_decrypt_2(
                key_handle,
                self.decrypt,
                mode,
                in_data.clone(),
                iv_in.clone(),
            )
        })
        .context("TPM2_EncryptDecrypt2 failed")?;

        output::write_to_file(&self.output, out_data.value())?;
        info!(
            "{} data saved to {}",
            if self.decrypt {
                "decrypted"
            } else {
                "encrypted"
            },
            self.output.display()
        );

        if let Some(ref path) = self.iv_out {
            output::write_to_file(path, iv_out.value())?;
            info!("IV out saved to {}", path.display());
        }

        Ok(())
    }
}
