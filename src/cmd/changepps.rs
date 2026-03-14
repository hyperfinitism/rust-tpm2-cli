use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Replace the platform primary seed and flush resident objects.
///
/// Wraps TPM2_ChangePPS (raw FFI).
#[derive(Parser)]
pub struct ChangePpsCmd {
    /// Auth value for the platform hierarchy
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,
}

impl ChangePpsCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(ESYS_TR_RH_PLATFORM, auth.value())?;
        }

        unsafe {
            let rc = Esys_ChangePPS(
                raw.ptr(),
                ESYS_TR_RH_PLATFORM,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
            );
            if rc != 0 {
                anyhow::bail!("Esys_ChangePPS failed: 0x{rc:08x}");
            }
        }

        info!("platform primary seed changed");
        Ok(())
    }
}
