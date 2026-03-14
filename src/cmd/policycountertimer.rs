use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Assert policy bound to the TPM clock/counter.
///
/// Wraps TPM2_PolicyCounterTimer (raw FFI).
#[derive(Parser)]
pub struct PolicyCounterTimerCmd {
    /// Policy session context file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Operand B (hex bytes for comparison)
    #[arg(long = "operand-b")]
    pub operand_b: String,

    /// Offset in the TPMS_TIME_INFO structure
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Operation (eq, neq, sgt, ugt, slt, ult, sge, uge, sle, ule, bs, bc)
    #[arg(long = "operation", default_value = "eq")]
    pub operation: String,
}

impl PolicyCounterTimerCmd {
    #[allow(clippy::field_reassign_with_default)]
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let session_handle = raw.context_load(
            self.session
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid session path"))?,
        )?;

        let operand_bytes = hex::decode(&self.operand_b).context("invalid operand-b hex")?;
        let mut operand = TPM2B_OPERAND::default();
        operand.size = operand_bytes.len() as u16;
        operand.buffer[..operand_bytes.len()].copy_from_slice(&operand_bytes);

        let operation = parse::parse_tpm2_operation(&self.operation)?;

        unsafe {
            let rc = Esys_PolicyCounterTimer(
                raw.ptr(),
                session_handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &operand,
                self.offset,
                operation,
            );
            if rc != 0 {
                bail!("Esys_PolicyCounterTimer failed: 0x{rc:08x}");
            }
        }

        raw.context_save_to_file(session_handle, &self.session)?;
        info!("policy counter/timer asserted");
        Ok(())
    }
}
