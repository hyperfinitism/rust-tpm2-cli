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
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Increment a monotonic counter NV index.
///
/// Wraps TPM2_NV_Increment.
#[derive(Parser)]
pub struct NvIncrementCmd {
    /// NV index (hex, e.g. 0x01000001)
    #[arg(value_parser = parse_hex_u32)]
    pub nv_index: u32,

    /// Authorization hierarchy (o/owner, p/platform) or NV index itself
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Auth value for the hierarchy or NV index
    #[arg(short = 'P', long = "auth", value_parser = crate::parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl NvIncrementCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let nv_handle = NvIndexTpmHandle::new(self.nv_index)
            .map_err(|e| anyhow::anyhow!("invalid NV index 0x{:08x}: {e}", self.nv_index))?;
        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .with_context(|| format!("failed to load NV index 0x{:08x}", self.nv_index))?;

        let nv_auth = resolve_nv_auth(&mut ctx, &self.hierarchy, nv_handle)?;

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

        info!("NV index 0x{:08x} incremented", self.nv_index);
        Ok(())
    }
}
