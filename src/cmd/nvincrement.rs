// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::interface_types::reserved_handles::NvAuth;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::resolve_nv_auth;
use crate::parse::{self, NvAuthEntity, parse_nv_index};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct NvIncrementCmd {
    /// NV index (hex, e.g. 0x01000001)
    #[arg(value_parser = parse_nv_index)]
    pub nv_index: NvIndexTpmHandle,

    /// Authorization entity for the NV index (owner, platform, or nv-index)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Authorization value for the hierarchy or NV index
    #[arg(short = 'P', long = "auth", value_parser = crate::parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl NvIncrementCmd {
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
            match &nv_auth {
                NvAuth::Owner => {
                    ctx.tr_set_auth(tss_esapi::handles::ObjectHandle::Owner, auth.clone())
                        .context("tr_set_auth failed")?;
                }
                NvAuth::Platform => {
                    ctx.tr_set_auth(tss_esapi::handles::ObjectHandle::Platform, auth.clone())
                        .context("tr_set_auth failed")?;
                }
                NvAuth::NvIndex(h) => {
                    ctx.tr_set_auth((*h).into(), auth.clone())
                        .context("tr_set_auth failed")?;
                }
            }
        }

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.nv_increment(nv_auth, nv_idx.into())
        })
        .context("TPM2_NV_Increment failed")?;

        info!("NV index 0x{raw_nv_index:08x} incremented");
        Ok(())
    }
}
