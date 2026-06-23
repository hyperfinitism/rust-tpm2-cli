// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{Auth, MaxBuffer, SavedTpmContext};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct SequenceCompleteCmd {
    /// Sequence context file
    #[arg(short = 'c', long = "context")]
    pub context: PathBuf,

    /// Optional final input data file
    #[arg(short = 'i', long = "input")]
    pub input: Option<PathBuf>,

    /// Output file for the resulting digest
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Output file for the validation ticket
    #[arg(short = 't', long = "ticket")]
    pub ticket: Option<PathBuf>,

    /// Hierarchy for ticket computation (o/owner, n/null, etc.)
    #[arg(short = 'C', long = "hierarchy", default_value = "n", value_parser = parse::parse_hierarchy)]
    pub hierarchy: Hierarchy,

    /// Authorization value for the sequence
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl SequenceCompleteCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let data = std::fs::read(&self.context)
            .with_context(|| format!("reading context from {}", self.context.display()))?;
        let saved: SavedTpmContext =
            serde_json::from_slice(&data).context("failed to deserialize sequence context")?;
        let seq_handle = ctx.context_load(saved).context("context_load failed")?;
        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(seq_handle, auth.clone())
                .context("failed to set sequence authorization")?;
        }
        let buffer = match &self.input {
            Some(path) => {
                let input_data = std::fs::read(path)
                    .with_context(|| format!("reading input from {}", path.display()))?;
                MaxBuffer::try_from(input_data)
                    .map_err(|e| anyhow::anyhow!("input too large for TPM buffer: {e}"))?
            }
            None => MaxBuffer::default(),
        };
        let (digest, ticket) =
            execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
                ctx.sequence_complete(seq_handle, buffer, self.hierarchy)
            })
            .context("TPM2_SequenceComplete failed")?;

        if let Some(ref path) = self.output {
            output::write_to_file(path, digest.as_bytes())?;
            info!("digest saved to {}", path.display());
        } else {
            output::print_hex(digest.as_bytes());
        }

        if let (Some(path), Some(t)) = (&self.ticket, ticket) {
            let bytes = crate::ticket::marshall_ticket(&t);
            std::fs::write(path, bytes)
                .with_context(|| format!("writing ticket to {}", path.display()))?;
            info!("ticket saved to {}", path.display());
        }

        Ok(())
    }
}
