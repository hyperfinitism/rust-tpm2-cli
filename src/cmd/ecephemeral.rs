use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::raw_esys;

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
        let curve_id = parse_ecc_curve(&self.curve)?;

        let (q_bytes, counter) = raw_esys::ec_ephemeral(global.tcti.as_deref(), curve_id)
            .context("TPM2_EC_Ephemeral failed")?;

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

fn parse_ecc_curve(s: &str) -> anyhow::Result<u16> {
    use tss_esapi::constants::tss::*;
    match s.to_lowercase().as_str() {
        "ecc192" | "nistp192" => Ok(TPM2_ECC_NIST_P192),
        "ecc224" | "nistp224" => Ok(TPM2_ECC_NIST_P224),
        "ecc256" | "nistp256" => Ok(TPM2_ECC_NIST_P256),
        "ecc384" | "nistp384" => Ok(TPM2_ECC_NIST_P384),
        "ecc521" | "nistp521" => Ok(TPM2_ECC_NIST_P521),
        "bnp256" => Ok(TPM2_ECC_BN_P256),
        "bnp638" => Ok(TPM2_ECC_BN_P638),
        "sm2p256" | "sm2" => Ok(TPM2_ECC_SM2_P256),
        _ => bail!("unsupported ECC curve: {s}"),
    }
}
