// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{MaxBuffer, SavedTpmContext};

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Feed data into a hash or HMAC sequence.
///
/// Wraps TPM2_SequenceUpdate: sends additional data to an ongoing hash
/// or HMAC sequence.  The sequence context file is updated in place.
#[derive(Parser)]
pub struct SequenceUpdateCmd {
    /// Sequence context file (will be updated in place)
    #[arg(short = 'c', long = "context")]
    pub context: PathBuf,

    /// Input data file
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,
}

impl SequenceUpdateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        // Load the sequence context.
        let data = std::fs::read(&self.context)
            .with_context(|| format!("reading context from {}", self.context.display()))?;
        let saved: SavedTpmContext =
            serde_json::from_slice(&data).context("failed to deserialize sequence context")?;
        let seq_handle = ctx.context_load(saved).context("context_load failed")?;

        // Read input data.
        let input_data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let buffer = MaxBuffer::try_from(input_data)
            .map_err(|e| anyhow::anyhow!("input too large for TPM buffer: {e}"))?;

        // Update the sequence.
        ctx.execute_with_nullauth_session(|ctx| ctx.sequence_update(seq_handle, buffer))
            .map_err(|e| anyhow::anyhow!(e))
            .context("TPM2_SequenceUpdate failed")?;

        // Save the updated sequence context.
        let saved = ctx
            .context_save(seq_handle)
            .context("context_save failed")?;
        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.context, json)?;

        info!("sequence updated");
        Ok(())
    }
}
