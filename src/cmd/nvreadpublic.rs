// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use serde_json::json;
use tss_esapi::handles::NvIndexTpmHandle;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse::parse_hex_u32;

/// Read the public area of an NV index.
///
/// Wraps TPM2_NV_ReadPublic: displays the NV index attributes, size,
/// hash algorithm, and name.
#[derive(Parser)]
pub struct NvReadPublicCmd {
    /// NV index (hex, e.g. 0x01000001)
    #[arg(value_parser = parse_hex_u32)]
    pub nv_index: u32,
}

impl NvReadPublicCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let nv_handle = NvIndexTpmHandle::new(self.nv_index)
            .map_err(|e| anyhow::anyhow!("invalid NV index 0x{:08x}: {e}", self.nv_index))?;

        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .with_context(|| format!("failed to load NV index 0x{:08x}", self.nv_index))?;

        let (nv_public, name) = ctx
            .execute_without_session(|ctx| ctx.nv_read_public(nv_idx.into()))
            .context("TPM2_NV_ReadPublic failed")?;

        let output = json!({
            "nv_index": format!("0x{:08x}", self.nv_index),
            "name": hex::encode(name.value()),
            "hash_algorithm": format!("{:?}", nv_public.name_algorithm()),
            "attributes": format!("{:?}", nv_public.attributes()),
            "data_size": nv_public.data_size(),
        });

        println!("{}", serde_json::to_string_pretty(&output)?);
        Ok(())
    }
}
