// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse::{self, NvAuthEntity};
use crate::raw_esys::RawEsysContext;

/// Set bits in a bit-field NV index.
///
/// Wraps TPM2_NV_SetBits (raw FFI).
#[derive(Parser)]
pub struct NvSetBitsCmd {
    /// NV index (hex)
    #[arg()]
    pub nv_index: String,

    /// Authorization hierarchy (o/owner, p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Auth value
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Bits to set (hex u64 value)
    #[arg(short = 'i', long = "bits")]
    pub bits: String,
}

impl NvSetBitsCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let nv_index_val =
            parse::parse_hex_u32(&self.nv_index).map_err(|e| anyhow::anyhow!("{e}"))?;
        let nv_handle = raw.tr_from_tpm_public(nv_index_val)?;

        let auth_handle = RawEsysContext::resolve_nv_auth_entity(self.hierarchy, nv_handle);

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.as_bytes())?;
        }

        let stripped = self
            .bits
            .strip_prefix("0x")
            .or_else(|| self.bits.strip_prefix("0X"))
            .unwrap_or(&self.bits);
        let bits: u64 = u64::from_str_radix(stripped, 16)
            .map_err(|_| anyhow::anyhow!("invalid bits value: {}", self.bits))?;

        unsafe {
            let rc = Esys_NV_SetBits(
                raw.ptr(),
                auth_handle,
                nv_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                bits,
            );
            if rc != 0 {
                anyhow::bail!("Esys_NV_SetBits failed: 0x{rc:08x}");
            }
        }

        info!("NV index 0x{nv_index_val:08x} bits set to 0x{bits:016x}");
        Ok(())
    }
}
