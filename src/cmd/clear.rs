// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;

/// Clear the TPM -- removes all loaded objects, sessions, and saved contexts.
///
/// By default uses the lockout hierarchy. Use `-c` to specify a different
/// authorization handle (owner, platform, lockout).
#[derive(Parser)]
pub struct ClearCmd {
    /// Authorization handle (o/owner, p/platform, l/lockout)
    #[arg(short = 'c', long = "auth", default_value = "l")]
    pub auth_handle: String,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl ClearCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let auth = parse::parse_auth_handle(&self.auth_handle)?;

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.clear(auth)?;
            Ok(())
        })
        .context("TPM2_Clear failed")?;

        info!("TPM cleared");
        Ok(())
    }
}
