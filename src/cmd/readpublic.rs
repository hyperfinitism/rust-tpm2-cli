// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::parse_context_source;

/// Read the public area of a loaded object.
#[derive(Parser)]
pub struct ReadPublicCmd {
    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Output file for the public area (binary)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

impl ReadPublicCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context)?;

        let (public, name, qualified_name) = ctx
            .execute_without_session(|ctx| ctx.read_public(key_handle))
            .context("TPM2_ReadPublic failed")?;

        println!("name: 0x{}", hex::encode(name.value()));
        println!("qualified name: 0x{}", hex::encode(qualified_name.value()));
        println!("{public:#?}");

        if let Some(ref path) = self.output {
            let pub_bytes = public.marshall().context("failed to marshal public")?;
            output::write_to_file(path, &pub_bytes)?;
            info!("public area saved to {}", path.display());
        }

        Ok(())
    }
}
