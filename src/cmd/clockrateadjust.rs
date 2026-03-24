// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Adjust the rate of advance of the TPM clock.
///
/// Wraps TPM2_ClockRateAdjust (raw FFI).
#[derive(Parser)]
pub struct ClockRateAdjustCmd {
    /// Auth hierarchy (o/owner or p/platform)
    #[arg(short = 'c', long = "hierarchy", default_value = "o", value_parser = parse::parse_esys_hierarchy)]
    pub hierarchy: u32,

    /// Auth value
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Rate adjustment (slower, slow, medium, fast, faster)
    #[arg()]
    pub rate: String,
}

impl ClockRateAdjustCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let auth_handle = self.hierarchy;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.as_bytes())?;
        }

        let rate_adjust: TPM2_CLOCK_ADJUST = match self.rate.to_lowercase().as_str() {
            "slower" => TPM2_CLOCK_COARSE_SLOWER,
            "slow" => TPM2_CLOCK_FINE_SLOWER,
            "medium" | "none" => TPM2_CLOCK_NO_CHANGE,
            "fast" => TPM2_CLOCK_FINE_FASTER,
            "faster" => TPM2_CLOCK_COARSE_FASTER,
            _ => anyhow::bail!(
                "invalid rate: {}; use slower/slow/medium/fast/faster",
                self.rate
            ),
        };

        unsafe {
            let rc = Esys_ClockRateAdjust(
                raw.ptr(),
                auth_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                rate_adjust,
            );
            if rc != 0 {
                anyhow::bail!("Esys_ClockRateAdjust failed: 0x{rc:08x}");
            }
        }

        info!("clock rate adjusted to {}", self.rate);
        Ok(())
    }
}
