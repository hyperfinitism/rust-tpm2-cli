// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::output;
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;

/// Unseal data previously sealed to a TPM object.
#[derive(Parser)]
pub struct UnsealCmd {
    /// Sealed object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Auth value for the sealed object
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Output file for the unsealed data
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl UnsealCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let obj_handle = load_object_from_source(&mut ctx, &self.context)?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(obj_handle, auth.clone())
                .context("failed to set sealed object auth")?;
        }

        let session_path = self.session.as_deref();
        let sensitive =
            execute_with_optional_session(&mut ctx, session_path, |ctx| ctx.unseal(obj_handle))
                .context("TPM2_Unseal failed")?;

        let bytes = sensitive.as_bytes();

        if let Some(ref path) = self.output {
            output::write_to_file(path, bytes)?;
            info!("unsealed {} bytes to {}", bytes.len(), path.display());
        } else {
            output::write_binary_stdout(bytes)?;
        }

        Ok(())
    }
}
