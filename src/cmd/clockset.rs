// SPDX-License-Identifier: Apache-2.0

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
pub struct ClockSetCmd {
    /// Authorization hierarchy (owner or platform)
    #[arg(short = 'c', long = "hierarchy", default_value = "o", value_parser = parse::parse_owner_or_platform_auth_handle)]
    pub hierarchy: AuthHandle,

    /// Authorization value
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// New clock value (milliseconds)
    #[arg()]
    pub new_time: u64,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl ClockSetCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(self.hierarchy.into(), auth.clone())
                .context("failed to set clock authorization")?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.clock_set(self.hierarchy, self.new_time)
        })
        .context("TPM2_ClockSet failed")?;

        info!("clock set to {}", self.new_time);
        Ok(())
    }
}
