// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{load_nv_index, nv_auth_from_entity, set_nv_auth};
use crate::parse::{self, NvAuthEntity};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct NvWriteLockCmd {
    /// NV index (hex)
    #[arg(value_parser = parse::parse_nv_index)]
    pub nv_index: tss_esapi::handles::NvIndexTpmHandle,

    /// Authorization entity for the NV index (owner, platform, or nv-index)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Authorization value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl NvWriteLockCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let nv_handle = load_nv_index(&mut ctx, self.nv_index)?;

        let nv_auth = nv_auth_from_entity(self.hierarchy, nv_handle);

        if let Some(ref auth) = self.auth {
            set_nv_auth(&mut ctx, nv_auth, auth.clone())?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.nv_write_lock(nv_auth, nv_handle)
        })
        .context("TPM2_NV_WriteLock failed")?;

        info!("NV index 0x{:08x} write-locked", u32::from(self.nv_index));
        Ok(())
    }
}
