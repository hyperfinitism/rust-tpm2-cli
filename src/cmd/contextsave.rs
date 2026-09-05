// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::parse_context_source;
#[derive(Parser)]
pub struct ContextSaveCmd {
    /// Object to save (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Output file for the saved context
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl ContextSaveCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let handle = load_object_from_source(&mut ctx, &self.context)?;

        let saved = ctx
            .context_save(handle)
            .context("TPM2_ContextSave failed")?;

        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.output, json)
            .with_context(|| format!("writing context to {}", self.output.display()))?;

        info!("context saved to {}", self.output.display());
        Ok(())
    }
}
