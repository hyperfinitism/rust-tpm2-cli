use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::SensitiveData;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Add external entropy to the TPM RNG state.
///
/// Wraps TPM2_StirRandom.
#[derive(Parser)]
pub struct StirRandomCmd {
    /// Input file containing entropy data
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,
}

impl StirRandomCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading entropy from {}", self.input.display()))?;
        let sensitive =
            SensitiveData::try_from(data).map_err(|e| anyhow::anyhow!("input too large: {e}"))?;

        ctx.execute_without_session(|ctx| ctx.stir_random(sensitive))
            .context("TPM2_StirRandom failed")?;

        info!("entropy added to TPM RNG");
        Ok(())
    }
}
