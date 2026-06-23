// SPDX-License-Identifier: Apache-2.0

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
#[derive(Parser)]
pub struct EncryptDecrypt2Cmd {
    /// Key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Authorization value for the key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Decrypt instead of encrypting
    #[arg(short = 'd', long = "decrypt")]
    pub decrypt: bool,

    /// Symmetric mode (cfb, cbc, ecb, ofb, ctr, null)
    #[arg(short = 'G', long = "mode", default_value = "null", value_parser = parse::parse_symmetric_mode)]
    pub mode: SymmetricMode,

    /// Input file for the initialization vector
    #[arg(short = 'i', long = "iv")]
    pub iv: Option<PathBuf>,

    /// Output file for the processed data
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Output file for the updated initialization vector
    #[arg(long = "iv-out")]
    pub iv_out: Option<PathBuf>,

    /// Input data file
    #[arg()]
    pub input: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl EncryptDecrypt2Cmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let key_handle = load_key_from_source(&mut ctx, &self.key_context)?;

        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(key_handle.into(), auth.clone())
                .context("failed to set key authorization")?;
        }

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let data =
            MaxBuffer::try_from(data).map_err(|e| anyhow::anyhow!("input too large: {e}"))?;
        let iv = match &self.iv {
            Some(path) => {
                let value = std::fs::read(path)
                    .with_context(|| format!("reading IV from {}", path.display()))?;
                InitialValue::try_from(value).map_err(|e| anyhow::anyhow!("invalid IV: {e}"))?
            }
            None => InitialValue::default(),
        };

        let (out_data, out_iv) =
            execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
                ctx.encrypt_decrypt_2(
                    key_handle,
                    self.decrypt,
                    self.mode,
                    data.clone(),
                    iv.clone(),
                )
            })
            .context("TPM2_EncryptDecrypt2 failed")?;

        output::write_to_file(&self.output, out_data.as_bytes())?;
        if let Some(path) = &self.iv_out {
            output::write_to_file(path, out_iv.as_bytes())?;
        }

        info!("symmetric operation completed");
        Ok(())
    }
}
