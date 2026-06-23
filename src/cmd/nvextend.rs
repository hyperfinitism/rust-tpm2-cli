// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::interface_types::reserved_handles::NvAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::Auth;
use tss_esapi::structures::MaxNvBuffer;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::resolve_nv_auth;
use crate::parse::{self, NvAuthEntity};

/// Extend an NV index with additional data.
///
/// Wraps TPM2_NV_Extend.
#[derive(Parser)]
pub struct NvExtendCmd {
    /// NV index (hex, e.g. 0x01000001)
    #[arg()]
    pub nv_index: String,

    /// Authorization hierarchy (o/owner, p/platform) or "index"
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Auth value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Input data file to extend
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,
}

impl NvExtendCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let nv_index_val =
            parse::parse_hex_u32(&self.nv_index).map_err(|e| anyhow::anyhow!("{e}"))?;
        let nv_handle = NvIndexTpmHandle::new(nv_index_val)
            .map_err(|e| anyhow::anyhow!("invalid NV index 0x{nv_index_val:08x}: {e}"))?;
        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .with_context(|| format!("failed to load NV index 0x{nv_index_val:08x}"))?;

        let nv_auth = resolve_nv_auth(&mut ctx, nv_auth_entity_name(self.hierarchy), nv_handle)?;

        if let Some(ref auth) = self.auth {
            set_nv_auth(&mut ctx, &nv_auth, auth)?;
        }

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let nv_data = MaxNvBuffer::try_from(data.clone())
            .map_err(|e| anyhow::anyhow!("NV extend input: {e}"))?;

        ctx.set_sessions((Some(AuthSession::Password), None, None));
        let result = ctx
            .nv_extend(nv_auth, nv_idx.into(), nv_data)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        result.context("TPM2_NV_Extend failed")?;

        info!(
            "NV index 0x{nv_index_val:08x} extended with {} bytes",
            data.len()
        );
        Ok(())
    }
}

fn nv_auth_entity_name(entity: NvAuthEntity) -> &'static str {
    match entity {
        NvAuthEntity::Owner => "owner",
        NvAuthEntity::Platform => "platform",
        NvAuthEntity::NvIndex => "index",
    }
}

fn set_nv_auth(ctx: &mut tss_esapi::Context, nv_auth: &NvAuth, auth: &Auth) -> anyhow::Result<()> {
    match nv_auth {
        NvAuth::Owner => {
            ctx.tr_set_auth(tss_esapi::handles::ObjectHandle::Owner, auth.clone())
                .context("tr_set_auth failed")?;
        }
        NvAuth::Platform => {
            ctx.tr_set_auth(tss_esapi::handles::ObjectHandle::Platform, auth.clone())
                .context("tr_set_auth failed")?;
        }
        NvAuth::NvIndex(handle) => {
            ctx.tr_set_auth((*handle).into(), auth.clone())
                .context("tr_set_auth failed")?;
        }
    }
    Ok(())
}
