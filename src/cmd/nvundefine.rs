// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::{NvIndexTpmHandle, ObjectHandle, TpmHandle};

use tss_esapi::interface_types::reserved_handles::Provision;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse::{self, parse_hex_u32};
use crate::session::execute_with_optional_session;

/// Remove an NV index from the TPM.
///
/// The hierarchy used must match the one that authorized creation of the index
/// (`-C o` for owner-created indices, `-C p` for platform-created).
///
/// Use `--special` for platform-created indices with TPMA_NV_POLICY_DELETE set.
#[derive(Parser)]
pub struct NvUndefineCmd {
    /// NV index handle to remove (hex, e.g. 0x01400001)
    #[arg(value_parser = parse_hex_u32)]
    pub nv_index: u32,

    /// Authorization hierarchy (o/owner, p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_provision)]
    pub hierarchy: Provision,

    /// Authorization value for the hierarchy
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,

    /// Use NV_UndefineSpaceSpecial (for platform-created indices with policydelete)
    #[arg(long = "special")]
    pub special: bool,
}

impl NvUndefineCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let nv_tpm_handle = NvIndexTpmHandle::new(self.nv_index)
            .map_err(|e| anyhow::anyhow!("invalid NV index handle: {e}"))?;

        if let Some(ref auth_str) = self.auth {
            let auth_value = parse::parse_auth(auth_str)?;
            let hier_obj: ObjectHandle = parse::provision_to_hierarchy_auth(self.hierarchy).into();
            ctx.tr_set_auth(hier_obj, auth_value)
                .context("failed to set hierarchy auth")?;
        }

        let tpm_handle: TpmHandle = nv_tpm_handle.into();
        let nv_index_handle = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .context("failed to load NV index handle")?;

        let session_path = self.session.as_deref();
        if self.special {
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.nv_undefine_space_special(self.hierarchy, nv_index_handle.into())
            })
            .context("TPM2_NV_UndefineSpaceSpecial failed")?;
        } else {
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.nv_undefine_space(self.hierarchy, nv_index_handle.into())
            })
            .context("TPM2_NV_UndefineSpace failed")?;
        }

        info!("NV index 0x{:08x} undefined", self.nv_index);
        Ok(())
    }
}
