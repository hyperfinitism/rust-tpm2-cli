// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Enable or disable use of a hierarchy and its associated NV storage.
///
/// Wraps TPM2_HierarchyControl (raw FFI).
#[derive(Parser)]
pub struct HierarchyControlCmd {
    /// Auth hierarchy (p/platform or o/owner)
    #[arg(short = 'C', long = "hierarchy", value_parser = parse::parse_esys_hierarchy)]
    pub auth_hierarchy: u32,

    /// Hierarchy to enable/disable (o/owner, e/endorsement, p/platform, n/null)
    #[arg(value_parser = parse::parse_tpm2_rh_hierarchy)]
    pub enable: u32,

    /// Auth value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Set state (true=enable, false=disable)
    #[arg(short = 's', long = "state", default_value = "true")]
    pub state: bool,
}

impl HierarchyControlCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let auth_handle = self.auth_hierarchy;

        if let Some(ref auth) = self.auth {
            raw.set_auth(auth_handle, auth.as_bytes())?;
        }

        let state: TPMI_YES_NO = if self.state { 1 } else { 0 };

        unsafe {
            let rc = Esys_HierarchyControl(
                raw.ptr(),
                auth_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                self.enable,
                state,
            );
            if rc != 0 {
                anyhow::bail!("Esys_HierarchyControl failed: 0x{rc:08x}");
            }
        }

        info!(
            "hierarchy {} {}",
            self.enable,
            if self.state { "enabled" } else { "disabled" }
        );
        Ok(())
    }
}
