// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;

use tss_esapi::handles::AuthHandle;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;

/// Enable or disable the TPM2_Clear command.
///
/// Wraps TPM2_ClearControl.
#[derive(Parser)]
pub struct ClearControlCmd {
    /// Auth handle (p/platform or l/lockout)
    #[arg(short = 'C', long = "hierarchy", value_parser = parse::parse_auth_handle)]
    pub hierarchy: AuthHandle,

    /// Auth value for the hierarchy
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Set to disable clear (true) or enable clear (false)
    #[arg(short = 's', long = "disable-clear", default_value = "true")]
    pub disable: bool,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl ClearControlCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(self.hierarchy.into(), auth)
                .context("tr_set_auth failed")?;
        }

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.clear_control(self.hierarchy, self.disable)
        })
        .context("TPM2_ClearControl failed")?;

        info!(
            "clear control set: clear is {}",
            if self.disable { "DISABLED" } else { "ENABLED" }
        );
        Ok(())
    }
}
