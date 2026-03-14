// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::MaxBuffer;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::output;
use crate::parse::{self, parse_hex_u32};
use crate::session::execute_with_optional_session;

/// Compute an HMAC using the TPM.
///
/// Wraps TPM2_HMAC: computes an HMAC over the input data using the
/// specified loaded HMAC key and hash algorithm.
#[derive(Parser)]
pub struct HmacCmd {
    /// HMAC key context file path
    #[arg(
        short = 'c',
        long = "key-context",
        conflicts_with = "key_context_handle"
    )]
    pub key_context: Option<PathBuf>,

    /// HMAC key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "key-context-handle", value_parser = parse_hex_u32, conflicts_with = "key_context")]
    pub key_context_handle: Option<u32>,

    /// Auth value for the key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Hash algorithm (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Input data file (reads from stdin if not provided)
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Output file for the HMAC digest
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl HmacCmd {
    fn key_context_source(&self) -> anyhow::Result<ContextSource> {
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

        let key_handle = load_object_from_source(&mut ctx, &self.key_context_source()?)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(key_handle, auth)
                .context("tr_set_auth failed")?;
        }

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let buffer = MaxBuffer::try_from(data)
            .map_err(|e| anyhow::anyhow!("input too large for TPM buffer: {e}"))?;

        let session_path = self.session.as_deref();
        let digest = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.hmac(key_handle, buffer.clone(), hash_alg)
        })
        .context("TPM2_HMAC failed")?;

        if let Some(ref path) = self.output {
            output::write_to_file(path, digest.value())?;
            info!("HMAC digest saved to {}", path.display());
        } else {
            output::print_hex(digest.value());
        }

        Ok(())
    }
}
