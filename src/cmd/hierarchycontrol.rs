use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Enable or disable use of a hierarchy and its associated NV storage.
///
/// Wraps TPM2_HierarchyControl (raw FFI).
#[derive(Parser)]
pub struct HierarchyControlCmd {
    /// Auth hierarchy (p/platform or o/owner)
    #[arg(short = 'C', long = "hierarchy")]
    pub auth_hierarchy: String,

    /// Hierarchy to enable/disable (o/owner, e/endorsement, p/platform, n/null)
    #[arg()]
    pub enable: String,

    /// Auth value
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Set state (true=enable, false=disable)
    #[arg(short = 's', long = "state", default_value = "true")]
    pub state: bool,
}

impl HierarchyControlCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let auth_handle = RawEsysContext::resolve_hierarchy(&self.auth_hierarchy)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.value())?;
        }

        let enable_hierarchy = match self.enable.to_lowercase().as_str() {
            "o" | "owner" => TPM2_RH_OWNER,
            "e" | "endorsement" => TPM2_RH_ENDORSEMENT,
            "p" | "platform" => TPM2_RH_PLATFORM,
            "n" | "null" => TPM2_RH_NULL,
            _ => anyhow::bail!("unknown hierarchy: {}", self.enable),
        };

        let state: TPMI_YES_NO = if self.state { 1 } else { 0 };

        unsafe {
            let rc = Esys_HierarchyControl(
                raw.ptr(),
                auth_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                enable_hierarchy,
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
