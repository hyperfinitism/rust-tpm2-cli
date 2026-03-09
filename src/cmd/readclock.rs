use clap::Parser;
use serde_json::json;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::raw_esys::RawEsysContext;

/// Read the current TPM clock and time values.
///
/// Wraps TPM2_ReadClock (raw FFI).
#[derive(Parser)]
pub struct ReadClockCmd {}

impl ReadClockCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        unsafe {
            let mut current_time: *mut TPMS_TIME_INFO = std::ptr::null_mut();

            let rc = Esys_ReadClock(
                raw.ptr(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &mut current_time,
            );
            if rc != 0 {
                anyhow::bail!("Esys_ReadClock failed: 0x{rc:08x}");
            }

            let t = &*current_time;
            let output = json!({
                "time": t.time,
                "clock_info": {
                    "clock": t.clockInfo.clock,
                    "reset_count": t.clockInfo.resetCount,
                    "restart_count": t.clockInfo.restartCount,
                    "safe": t.clockInfo.safe == 1,
                }
            });

            Esys_Free(current_time as *mut _);

            println!("{}", serde_json::to_string_pretty(&output)?);
        }

        Ok(())
    }
}
