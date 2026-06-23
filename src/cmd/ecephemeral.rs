// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;

/// Create an ephemeral key for two-phase key exchange.
///
/// Wraps TPM2_EC_Ephemeral: generates an ephemeral public point and
/// counter for the given ECC curve.  Unlike ecdhkeygen, this does not
/// require a loaded key.
#[derive(Parser)]
pub struct EcEphemeralCmd {
    /// ECC curve (e.g. ecc256, ecc384, ecc521)
    #[arg()]
    pub curve: String,

    /// Output file for the ephemeral public point Q
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Output file for the counter value
    #[arg(short = 't', long = "counter")]
    pub counter: Option<PathBuf>,
}

impl EcEphemeralCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let curve = parse::parse_ecc_curve(&self.curve).map_err(anyhow::Error::msg)?;
        let mut ctx = create_context(global.tcti.as_deref())?;

        let (q_point, counter) = ctx
            .ec_ephemeral(curve)
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
            std::fs::write(path, counter.to_le_bytes())
                .with_context(|| format!("writing counter to {}", path.display()))?;
            info!("counter saved to {}", path.display());
        }

        info!("ec_ephemeral succeeded (counter={counter})");
        Ok(())
    }
}

fn ecc_point_to_bytes(point: &tss_esapi::structures::EccPoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(point.x().len() + point.y().len());
    out.extend_from_slice(point.x().as_bytes());
    out.extend_from_slice(point.y().as_bytes());
    out
}
