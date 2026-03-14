use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Send TPM2_Startup command.
#[derive(Parser)]
pub struct StartupCmd {
    /// Send Startup(CLEAR) — reset TPM state
    #[arg(short = 'c', long = "clear")]
    pub clear: bool,
}

impl StartupCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let startup_type = if self.clear {
            tss_esapi::constants::StartupType::Clear
        } else {
            tss_esapi::constants::StartupType::State
        };

        ctx.startup(startup_type).context("TPM2_Startup failed")?;
        info!("TPM2_Startup successful");
        Ok(())
    }
}
