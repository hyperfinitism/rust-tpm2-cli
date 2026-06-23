// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::structures::Auth;
use tss_esapi::structures::MaxNvBuffer;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{resolve_nv_auth, set_nv_auth};
use crate::parse::{self, NvAuthEntity};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct NvExtendCmd {
    /// NV index (hex, e.g. 0x01000001)
    #[arg(value_parser = parse::parse_nv_index)]
    pub nv_index: NvIndexTpmHandle,

    /// Authorization entity for the NV index (owner, platform, or nv-index)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Authorization value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Input data file to extend
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl NvExtendCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let nv_handle = self.nv_index;
        let raw_nv_index = u32::from(nv_handle);
        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .with_context(|| format!("failed to load NV index 0x{raw_nv_index:08x}"))?;

        let nv_auth = resolve_nv_auth(&mut ctx, self.hierarchy, nv_handle)?;

        if let Some(ref auth) = self.auth {
            set_nv_auth(&mut ctx, nv_auth, auth.clone())?;
        }

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let nv_data = MaxNvBuffer::try_from(data.clone())
            .map_err(|e| anyhow::anyhow!("NV extend input: {e}"))?;

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.nv_extend(nv_auth, nv_idx.into(), nv_data)
        })
        .context("TPM2_NV_Extend failed")?;

        info!(
            "NV index 0x{:08x} extended with {} bytes",
            raw_nv_index,
            data.len()
        );
        Ok(())
    }
}
