// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse::{self, NvAuthEntity};
use crate::raw_esys::RawEsysContext;

/// Extend an NV index with additional data.
///
/// Wraps TPM2_NV_Extend (raw FFI).
#[derive(Parser)]
pub struct NvExtendCmd {
    /// NV index (hex, e.g. 0x01000001)
    #[arg()]
    pub nv_index: String,

    /// Authorization hierarchy (o/owner, p/platform) or "index"
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Auth value
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Input data file to extend
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,
}

impl NvExtendCmd {
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

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;

        let mut nv_data = TPM2B_MAX_NV_BUFFER::default();
        let len = data.len().min(nv_data.buffer.len());
        nv_data.size = len as u16;
        nv_data.buffer[..len].copy_from_slice(&data[..len]);

        unsafe {
            let rc = Esys_NV_Extend(
                raw.ptr(),
                auth_handle,
                nv_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &nv_data,
            );
            if rc != 0 {
                anyhow::bail!("Esys_NV_Extend failed: 0x{rc:08x}");
            }
        }

        info!(
            "NV index 0x{nv_index_val:08x} extended with {} bytes",
            data.len()
        );
        Ok(())
    }
}
