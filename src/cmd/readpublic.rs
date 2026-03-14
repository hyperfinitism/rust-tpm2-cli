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
use crate::parse::parse_hex_u32;

/// Read the public area of a loaded object.
#[derive(Parser)]
pub struct ReadPublicCmd {
    /// Object context file path
    #[arg(short = 'c', long = "context", conflicts_with = "context_handle")]
    pub context: Option<PathBuf>,

    /// Object handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "context-handle", value_parser = parse_hex_u32, conflicts_with = "context")]
    pub context_handle: Option<u32>,

    /// Output file for the public area (binary)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

impl ReadPublicCmd {
    fn context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.context, self.context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!("exactly one of --context or --context-handle must be provided"),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context_source()?)?;

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
