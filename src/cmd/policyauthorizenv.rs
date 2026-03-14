// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Assert policy using a policy stored in an NV index.
///
/// Wraps TPM2_PolicyAuthorizeNV (raw FFI).
#[derive(Parser)]
pub struct PolicyAuthorizeNvCmd {
    /// Policy session context file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// NV index containing the policy (hex, e.g. 0x01000001)
    #[arg(short = 'i', long = "nv-index")]
    pub nv_index: String,

    /// Auth hierarchy for the NV index (o/p/e or nv)
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Auth value for the hierarchy
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,
}

impl PolicyAuthorizeNvCmd {
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

        unsafe {
            let rc = Esys_PolicyAuthorizeNV(
                raw.ptr(),
                auth_handle,
                nv_handle,
                session_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
            );
            if rc != 0 {
                anyhow::bail!("Esys_PolicyAuthorizeNV failed: 0x{rc:08x}");
            }
        }

        raw.context_save_to_file(session_handle, &self.session)?;
        info!("policy authorize NV asserted");
        Ok(())
    }
}
