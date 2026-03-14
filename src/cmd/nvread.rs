// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::resolve_nv_auth;
use crate::output;
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Read data from an NV index.
#[derive(Parser)]
pub struct NvReadCmd {
    /// NV index handle (hex, e.g. 0x01400001)
    #[arg(value_parser = parse_hex_u32)]
    pub nv_index: u32,

    /// Authorization hierarchy (o/owner, p/platform, or the NV index itself)
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Number of bytes to read
    #[arg(short = 's', long = "size")]
    pub size: Option<u16>,

    /// Offset within the NV area
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Output file
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl NvReadCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let nv_handle = NvIndexTpmHandle::new(self.nv_index)
            .map_err(|e| anyhow::anyhow!("invalid NV index handle: {e}"))?;

        // Determine size from NV public if not specified
        let size = match self.size {
            Some(s) => s,
            None => {
                let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
                let nv_idx = ctx
                    .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
                    .context("failed to load NV index")?;
                let (nv_public, _) = ctx
                    .execute_without_session(|ctx| ctx.nv_read_public(nv_idx.into()))
                    .context("TPM2_NV_ReadPublic failed")?;
                nv_public.data_size() as u16
            }
        };

        let nv_auth = resolve_nv_auth(&mut ctx, &self.hierarchy, nv_handle)?;

        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .context("failed to load NV index")?;

        let session_path = self.session.as_deref();
        let data = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.nv_read(nv_auth, nv_idx.into(), size, self.offset)
        })
        .context("TPM2_NV_Read failed")?;

        let bytes = data.value();

        if let Some(ref path) = self.output {
            output::write_to_file(path, bytes)?;
            info!("wrote {} bytes to {}", bytes.len(), path.display());
        } else {
            output::print_hex(bytes);
        }

        Ok(())
    }
}
