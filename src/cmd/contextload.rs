// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::SavedTpmContext;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Load a previously saved context back into the TPM.
///
/// Wraps TPM2_ContextLoad: restores an object (key, session, etc.) from a
/// previously saved context file.  The restored handle is saved to a new
/// context file.
#[derive(Parser)]
pub struct ContextLoadCmd {
    /// Input file containing the saved context (JSON)
    #[arg(short = 'c', long = "context")]
    pub context: PathBuf,

    /// Output file for the restored context
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl ContextLoadCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let data = std::fs::read(&self.context)
            .with_context(|| format!("reading context from {}", self.context.display()))?;
        let saved: SavedTpmContext =
            serde_json::from_slice(&data).context("failed to deserialize saved context")?;

        let handle = ctx.context_load(saved).context("TPM2_ContextLoad failed")?;

        // Save the restored handle to a new context file.
        let saved = ctx
            .context_save(handle)
            .context("context_save after load failed")?;
        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.output, json)
            .with_context(|| format!("writing context to {}", self.output.display()))?;

        info!("context loaded and saved to {}", self.output.display());
        Ok(())
    }
}
