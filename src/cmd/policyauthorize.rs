// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::{Digest, Name, Nonce, VerifiedTicket};
use tss_esapi::tss2_esys::TPMT_TK_VERIFIED;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

/// Approve a policy with an authorized signing key.
///
/// Wraps TPM2_PolicyAuthorize.
#[derive(Parser)]
pub struct PolicyAuthorizeCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Approved policy digest file
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Policy reference (digest) (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = crate::parse::parse_qualification)]
    pub qualification: Option<crate::parse::Qualification>,

    /// Signing key name file
    #[arg(short = 'n', long = "name")]
    pub name: PathBuf,

    /// Verification ticket file
    #[arg(short = 't', long = "ticket")]
    pub ticket: PathBuf,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyAuthorizeCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let approved_data = std::fs::read(&self.input)
            .with_context(|| format!("reading approved policy from {}", self.input.display()))?;
        let approved_policy = Digest::try_from(approved_data)
            .map_err(|e| anyhow::anyhow!("invalid approved policy: {e}"))?;

        let policy_ref = match &self.qualification {
            Some(bytes) => Nonce::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Nonce::default(),
        };

        let name_data = std::fs::read(&self.name)
            .with_context(|| format!("reading name from {}", self.name.display()))?;
        let key_sign =
            Name::try_from(name_data).map_err(|e| anyhow::anyhow!("invalid name: {e}"))?;

        let ticket_data = std::fs::read(&self.ticket)
            .with_context(|| format!("reading ticket from {}", self.ticket.display()))?;
        let check_ticket = if ticket_data.len() >= std::mem::size_of::<TPMT_TK_VERIFIED>() {
            let tss_ticket: TPMT_TK_VERIFIED =
                unsafe { std::ptr::read(ticket_data.as_ptr() as *const TPMT_TK_VERIFIED) };
            VerifiedTicket::try_from(tss_ticket)
                .map_err(|e| anyhow::anyhow!("invalid ticket: {e}"))?
        } else {
            anyhow::bail!("ticket file too small");
        };

        ctx.policy_authorize(
            policy_session,
            approved_policy,
            policy_ref,
            &key_sign,
            check_ticket,
        )
        .context("TPM2_PolicyAuthorize failed")?;

        info!("policy authorize succeeded");

        if let Some(ref path) = self.policy {
            let digest = ctx
                .policy_get_digest(policy_session)
                .context("TPM2_PolicyGetDigest failed")?;
            std::fs::write(path, digest.as_bytes())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        Ok(())
    }
}
