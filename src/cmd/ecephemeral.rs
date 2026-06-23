// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::ecc::EccCurve;

use crate::cli::GlobalOpts;
use crate::cmd::ecc::ecc_point_to_bytes;
use crate::context::create_context;
use crate::parse;
#[derive(Parser)]
pub struct EcEphemeralCmd {
    /// ECC curve (e.g. ecc256, ecc384, ecc521)
    #[arg(value_parser = parse::parse_ecc_curve)]
    pub curve: EccCurve,

    /// Output file for the ephemeral public point Q
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Output file for the counter value
    #[arg(short = 't', long = "counter")]
    pub counter: Option<PathBuf>,
}

impl EcEphemeralCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let (q_point, counter) = ctx
            .ec_ephemeral(self.curve)
            .map_err(|e| anyhow::anyhow!(e))
            .context("TPM2_EC_Ephemeral failed")?;
        let q_bytes = ecc_point_to_bytes(&q_point);

        std::fs::write(&self.public, &q_bytes)
            .with_context(|| format!("writing public point to {}", self.public.display()))?;
        info!(
            "ephemeral public point Q saved to {}",
            self.public.display()
        );

        if let Some(ref path) = self.counter {
            std::fs::write(path, counter.to_be_bytes())
                .with_context(|| format!("writing counter to {}", path.display()))?;
            info!("counter saved to {}", path.display());
        }

        info!("ec_ephemeral succeeded (counter={counter})");
        Ok(())
    }
}
