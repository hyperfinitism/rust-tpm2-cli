use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Send TPM2_Shutdown command.
#[derive(Parser)]
pub struct ShutdownCmd {
    /// Send Shutdown(CLEAR) instead of Shutdown(STATE)
    #[arg(short = 'c', long = "clear")]
    pub clear: bool,
}

impl ShutdownCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let shutdown_type = if self.clear {
            tss_esapi::constants::StartupType::Clear
        } else {
            tss_esapi::constants::StartupType::State
        };

        ctx.shutdown(shutdown_type)
            .context("TPM2_Shutdown failed")?;
        info!("TPM2_Shutdown successful");
        Ok(())
    }
}
