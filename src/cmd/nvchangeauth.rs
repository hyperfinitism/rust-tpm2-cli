// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::load_nv_index;
use crate::parse;
use crate::session::execute_with_policy_session;
#[derive(Parser)]
pub struct NvChangeAuthCmd {
    /// NV index handle (hex, e.g. 0x01400001)
    #[arg(value_parser = parse::parse_nv_index)]
    pub nv_index: tss_esapi::handles::NvIndexTpmHandle,

    /// Current authorization value for the NV index
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// New authorization value
    #[arg(short = 'r', long = "new-auth", value_parser = parse::parse_auth)]
    pub new_auth: Auth,

    /// Policy session context file for NV index authorization
    #[arg(short = 'S', long = "policy-session")]
    pub policy_session: PathBuf,
}

impl NvChangeAuthCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let nv_handle = load_nv_index(&mut ctx, self.nv_index)?;

        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(nv_handle.into(), auth.clone())
                .context("failed to set NV index authorization")?;
        }

        execute_with_policy_session(&mut ctx, &self.policy_session, |ctx| {
            ctx.nv_change_auth(nv_handle, self.new_auth.clone())
        })
        .context("TPM2_NV_ChangeAuth failed")?;

        info!(
            "NV index 0x{:08x} authorization changed",
            u32::from(self.nv_index)
        );
        Ok(())
    }
}
