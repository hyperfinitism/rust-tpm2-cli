// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{Auth, MaxBuffer, SavedTpmContext};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct SequenceUpdateCmd {
    /// Sequence context file (will be updated in place)
    #[arg(short = 'c', long = "context")]
    pub context: PathBuf,

    /// Input data file
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Authorization value for the sequence
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl SequenceUpdateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let data = std::fs::read(&self.context)
            .with_context(|| format!("reading context from {}", self.context.display()))?;
        let saved: SavedTpmContext =
            serde_json::from_slice(&data).context("failed to deserialize sequence context")?;
        let seq_handle = ctx.context_load(saved).context("context_load failed")?;
        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(seq_handle, auth.clone())
                .context("failed to set sequence authorization")?;
        }
        let input_data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let buffer = MaxBuffer::try_from(input_data)
            .map_err(|e| anyhow::anyhow!("input too large for TPM buffer: {e}"))?;
        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.sequence_update(seq_handle, buffer)
        })
        .context("TPM2_SequenceUpdate failed")?;
        let saved = ctx
            .context_save(seq_handle)
            .context("context_save failed")?;
        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.context, json)?;

        info!("sequence updated");
        Ok(())
    }
}
