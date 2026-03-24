// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{MaxBuffer, SavedTpmContext};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;
use crate::parse;

/// Complete a hash or HMAC sequence and retrieve the result.
///
/// Wraps TPM2_SequenceComplete: finalizes an ongoing hash or HMAC sequence,
/// optionally providing additional data, and returns the final digest.
#[derive(Parser)]
pub struct SequenceCompleteCmd {
    /// Sequence context file
    #[arg(short = 'c', long = "context")]
    pub context: PathBuf,

    /// Optional final input data file
    #[arg(short = 'i', long = "input")]
    pub input: Option<PathBuf>,

    /// Output file for the resulting digest
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Output file for the validation ticket
    #[arg(short = 't', long = "ticket")]
    pub ticket: Option<PathBuf>,

    /// Hierarchy for ticket computation (o/owner, n/null, etc.)
    #[arg(short = 'C', long = "hierarchy", default_value = "n", value_parser = parse::parse_hierarchy)]
    pub hierarchy: Hierarchy,
}

impl SequenceCompleteCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        // Load the sequence context.
        let data = std::fs::read(&self.context)
            .with_context(|| format!("reading context from {}", self.context.display()))?;
        let saved: SavedTpmContext =
            serde_json::from_slice(&data).context("failed to deserialize sequence context")?;
        let seq_handle = ctx.context_load(saved).context("context_load failed")?;

        // Read optional final input data.
        let buffer = match &self.input {
            Some(path) => {
                let input_data = std::fs::read(path)
                    .with_context(|| format!("reading input from {}", path.display()))?;
                MaxBuffer::try_from(input_data)
                    .map_err(|e| anyhow::anyhow!("input too large for TPM buffer: {e}"))?
            }
            None => MaxBuffer::default(),
        };

        // Complete the sequence.
        let (digest, ticket) = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.sequence_complete(seq_handle, buffer, self.hierarchy)
            })
            .map_err(|e| anyhow::anyhow!(e))
            .context("TPM2_SequenceComplete failed")?;

        if let Some(ref path) = self.output {
            output::write_to_file(path, digest.as_bytes())?;
            info!("digest saved to {}", path.display());
        } else {
            output::print_hex(digest.as_bytes());
        }

        if let (Some(path), Some(t)) = (&self.ticket, ticket) {
            let tss_ticket: TPMT_TK_HASHCHECK = t
                .try_into()
                .map_err(|e| anyhow::anyhow!("failed to convert ticket: {e:?}"))?;
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &tss_ticket as *const TPMT_TK_HASHCHECK as *const u8,
                    std::mem::size_of::<TPMT_TK_HASHCHECK>(),
                )
            };
            std::fs::write(path, bytes)
                .with_context(|| format!("writing ticket to {}", path.display()))?;
            info!("ticket saved to {}", path.display());
        }

        Ok(())
    }
}
