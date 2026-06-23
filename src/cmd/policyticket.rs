// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::SessionHandle;
use tss_esapi::structures::{Digest, Name, Nonce, Timeout};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::{load_session_from_file, save_session_and_forget};
#[derive(Parser)]
pub struct PolicyTicketCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Timeout value (hex bytes)
    #[arg(long = "timeout", value_parser = parse::parse_hex_timeout)]
    pub timeout: Option<Timeout>,

    /// cpHash for the command being authorized (hex)
    #[arg(long = "cphash", value_parser = parse::parse_hex_digest)]
    pub cphash: Option<Digest>,

    /// Policy reference (hex)
    #[arg(long = "policy-ref", value_parser = parse::parse_hex_nonce)]
    pub policy_ref: Option<Nonce>,

    /// Key name (hex)
    #[arg(short = 'n', long = "name", value_parser = parse::parse_hex_name)]
    pub name: Name,

    /// Ticket file (binary)
    #[arg(short = 't', long = "ticket")]
    pub ticket: PathBuf,
}

impl PolicyTicketCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let timeout = self.timeout.clone().unwrap_or_default();
        let cp_hash_a = self.cphash.clone().unwrap_or_default();
        let policy_ref = self.policy_ref.clone().unwrap_or_default();
        let ticket_data = std::fs::read(&self.ticket)
            .with_context(|| format!("reading ticket from {}", self.ticket.display()))?;
        let ticket = crate::ticket::parse_auth_ticket(&ticket_data)?;

        ctx.policy_ticket(
            policy_session,
            timeout,
            cp_hash_a,
            policy_ref,
            self.name.clone(),
            ticket,
        )
        .context("TPM2_PolicyTicket failed")?;

        let session_handle = SessionHandle::from(policy_session);
        save_session_and_forget(ctx, session_handle, &self.session)?;
        info!("policy ticket asserted");
        Ok(())
    }
}
