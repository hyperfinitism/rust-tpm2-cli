// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::structures::Auth;

use tss_esapi::interface_types::reserved_handles::Provision;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::load_nv_index;
use crate::parse::{self, parse_nv_index};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct NvUndefineCmd {
    /// NV index handle to remove (hex, e.g. 0x01400001)
    #[arg(value_parser = parse_nv_index)]
    pub nv_index: tss_esapi::handles::NvIndexTpmHandle,

    /// Authorization hierarchy (owner or platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_provision)]
    pub hierarchy: Provision,

    /// Authorization value for the hierarchy
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl NvUndefineCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let nv_index_handle = load_nv_index(&mut ctx, self.nv_index)?;

        if let Some(ref auth) = self.auth {
            let hier_obj: ObjectHandle = parse::provision_to_hierarchy_auth(self.hierarchy).into();
            ctx.tr_set_auth(hier_obj, auth.clone())
                .context("failed to set hierarchy auth")?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.nv_undefine_space(self.hierarchy, nv_index_handle)
        })
        .context("TPM2_NV_UndefineSpace failed")?;

        info!("NV index 0x{:08x} undefined", u32::from(self.nv_index));
        Ok(())
    }
}
