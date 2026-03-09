use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Lock an NV index for writing (until next TPM reset).
///
/// Wraps TPM2_NV_WriteLock (raw FFI).
#[derive(Parser)]
pub struct NvWriteLockCmd {
    /// NV index (hex)
    #[arg()]
    pub nv_index: String,

    /// Authorization hierarchy (o/owner, p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Auth value
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,
}

impl NvWriteLockCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let nv_index_val =
            parse::parse_hex_u32(&self.nv_index).map_err(|e| anyhow::anyhow!("{e}"))?;
        let nv_handle = raw.tr_from_tpm_public(nv_index_val)?;

        let auth_handle = match self.hierarchy.to_lowercase().as_str() {
            "o" | "owner" => ESYS_TR_RH_OWNER,
            "p" | "platform" => ESYS_TR_RH_PLATFORM,
            _ => nv_handle,
        };

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.value())?;
        }

        unsafe {
            let rc = Esys_NV_WriteLock(
                raw.ptr(),
                auth_handle,
                nv_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
            );
            if rc != 0 {
                anyhow::bail!("Esys_NV_WriteLock failed: 0x{rc:08x}");
            }
        }

        info!("NV index 0x{nv_index_val:08x} write-locked");
        Ok(())
    }
}
