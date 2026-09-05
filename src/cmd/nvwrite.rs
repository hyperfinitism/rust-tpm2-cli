// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::structures::MaxNvBuffer;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::resolve_nv_auth;
use crate::parse::{self, NvAuthEntity, parse_nv_index};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct NvWriteCmd {
    /// NV index handle (hex, e.g. 0x01400001)
    #[arg(value_parser = parse_nv_index)]
    pub nv_index: NvIndexTpmHandle,

    /// Authorization entity for the NV index (owner, platform, or nv-index)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Input file (default: stdin)
    #[arg(short = 'i', long = "input")]
    pub input: Option<PathBuf>,

    /// Offset within the NV area
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl NvWriteCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let nv_handle = self.nv_index;
        let nv_auth = resolve_nv_auth(&mut ctx, self.hierarchy, nv_handle)?;

        let data = read_input(&self.input)?;
        let buffer =
            MaxNvBuffer::try_from(data).map_err(|e| anyhow::anyhow!("data too large: {e}"))?;

        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .context("failed to load NV index")?;

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.nv_write(nv_auth, nv_idx.into(), buffer.clone(), self.offset)
        })
        .context("TPM2_NV_Write failed")?;

        info!(
            "data written to NV index 0x{:08x}",
            u32::from(self.nv_index)
        );
        Ok(())
    }
}

fn read_input(path: &Option<PathBuf>) -> anyhow::Result<Vec<u8>> {
    match path {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display())),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).context("reading stdin")?;
            Ok(buf)
        }
    }
}
