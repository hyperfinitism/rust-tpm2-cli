// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Set the TPM clock to a new value.
///
/// Wraps TPM2_ClockSet (raw FFI).
#[derive(Parser)]
pub struct SetClockCmd {
    /// Auth hierarchy (o/owner or p/platform)
    #[arg(short = 'c', long = "hierarchy", default_value = "o", value_parser = parse::parse_esys_hierarchy)]
    pub hierarchy: u32,

    /// Auth value
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// New clock value (milliseconds)
    #[arg()]
    pub new_time: u64,
}

impl SetClockCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let auth_handle = self.hierarchy;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.as_bytes())?;
        }

        unsafe {
            let rc = Esys_ClockSet(
                raw.ptr(),
                auth_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                self.new_time,
            );
            if rc != 0 {
                anyhow::bail!("Esys_ClockSet failed: 0x{rc:08x}");
            }
        }

        info!("clock set to {}", self.new_time);
        Ok(())
    }
}
