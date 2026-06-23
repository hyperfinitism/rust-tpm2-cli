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
pub struct ClearCmd {
    /// Authorization handle (p/platform or l/lockout)
    #[arg(short = 'c', long = "hierarchy", default_value = "l", value_parser = parse::parse_platform_or_lockout_auth_handle)]
    pub auth_handle: AuthHandle,

    /// Authorization value for the hierarchy
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl ClearCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(self.auth_handle.into(), auth.clone())
                .context("failed to set hierarchy authorization")?;
        }

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.clear(self.auth_handle)?;
            Ok(())
        })
        .context("TPM2_Clear failed")?;

        info!("TPM cleared");
        Ok(())
    }
}
