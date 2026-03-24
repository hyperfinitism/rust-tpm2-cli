// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Replace the endorsement primary seed and flush resident objects.
///
/// Wraps TPM2_ChangeEPS (raw FFI).
#[derive(Parser)]
pub struct ChangeEpsCmd {
    /// Auth value for the platform hierarchy
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,
}

impl ChangeEpsCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(ESYS_TR_RH_PLATFORM, auth.as_bytes())?;
        }

        unsafe {
            let rc = Esys_ChangeEPS(
                raw.ptr(),
                ESYS_TR_RH_PLATFORM,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
            );
            if rc != 0 {
                anyhow::bail!("Esys_ChangeEPS failed: 0x{rc:08x}");
            }
        }

        info!("endorsement primary seed changed");
        Ok(())
    }
}
