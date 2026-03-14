// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Assert policy bound to NV index contents.
///
/// Wraps TPM2_PolicyNV (raw FFI).
#[derive(Parser)]
pub struct PolicyNvCmd {
    /// Policy session context file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// NV index (hex, e.g. 0x01000001)
    #[arg(short = 'i', long = "nv-index")]
    pub nv_index: String,

    /// Auth hierarchy for NV (o/p/e or nv)
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Auth value for the hierarchy
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Operand B (hex bytes for comparison)
    #[arg(long = "operand-b")]
    pub operand_b: String,

    /// Offset within the NV data
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Operation (eq, neq, sgt, ugt, slt, ult, sge, uge, sle, ule, bs, bc)
    #[arg(long = "operation", default_value = "eq")]
    pub operation: String,
}

impl PolicyNvCmd {
    #[allow(clippy::field_reassign_with_default)]
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let session_handle = raw.context_load(
            self.session
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid session path"))?,
        )?;

        let nv_handle = raw.resolve_nv_index(&self.nv_index)?;

        let auth_handle = if self.hierarchy == "nv" {
            nv_handle
        } else {
            RawEsysContext::resolve_hierarchy(&self.hierarchy)?
        };

        if let Some(ref auth_str) = self.auth {
            let a = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, a.value())?;
        }

        let operand_bytes = hex::decode(&self.operand_b).context("invalid operand-b hex")?;
        let mut operand = TPM2B_OPERAND::default();
        operand.size = operand_bytes.len() as u16;
        operand.buffer[..operand_bytes.len()].copy_from_slice(&operand_bytes);

        let operation = parse::parse_tpm2_operation(&self.operation)?;

        unsafe {
            let rc = Esys_PolicyNV(
                raw.ptr(),
                auth_handle,
                nv_handle,
                session_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &operand,
                self.offset,
                operation,
            );
            if rc != 0 {
                bail!("Esys_PolicyNV failed: 0x{rc:08x}");
            }
        }

        raw.context_save_to_file(session_handle, &self.session)?;
        info!("policy NV asserted");
        Ok(())
    }
}
