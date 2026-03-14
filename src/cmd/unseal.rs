// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::output;
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Unseal data previously sealed to a TPM object.
#[derive(Parser)]
pub struct UnsealCmd {
    /// Sealed object context file path
    #[arg(short = 'c', long = "context", conflicts_with = "context_handle")]
    pub context: Option<PathBuf>,

    /// Sealed object handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "context-handle", value_parser = parse_hex_u32, conflicts_with = "context")]
    pub context_handle: Option<u32>,

    /// Output file for the unsealed data
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl UnsealCmd {
    fn context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.context, self.context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!("exactly one of --context or --context-handle must be provided"),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let obj_handle = load_object_from_source(&mut ctx, &self.context_source()?)?;

        let session_path = self.session.as_deref();
        let sensitive =
            execute_with_optional_session(&mut ctx, session_path, |ctx| ctx.unseal(obj_handle))
                .context("TPM2_Unseal failed")?;

        let bytes = sensitive.value();

        if let Some(ref path) = self.output {
            output::write_to_file(path, bytes)?;
            info!("unsealed {} bytes to {}", bytes.len(), path.display());
        } else {
            output::write_binary_stdout(bytes)?;
        }

        Ok(())
    }
}
