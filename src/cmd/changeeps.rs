// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct ChangeEpsCmd {
    /// Authorization value for the platform hierarchy
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl ChangeEpsCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(ObjectHandle::Platform, auth.clone())
                .context("failed to set platform authorization")?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| ctx.change_eps())
            .context("TPM2_ChangeEPS failed")?;

        info!("endorsement primary seed changed");
        Ok(())
    }
}
