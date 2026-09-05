// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::AuthHandle;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct NvGlobalWriteLockCmd {
    /// Authorization hierarchy (owner or platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_owner_or_platform_auth_handle)]
    pub hierarchy: AuthHandle,

    /// Authorization value for the hierarchy
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl NvGlobalWriteLockCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(self.hierarchy.into(), auth.clone())
                .context("failed to set hierarchy authorization")?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.nv_global_write_lock(self.hierarchy)
        })
        .context("TPM2_NV_GlobalWriteLock failed")?;

        info!("global NV write lock set");
        Ok(())
    }
}
