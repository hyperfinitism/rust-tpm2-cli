// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::SessionHandle;
use tss_esapi::structures::SymmetricDefinition;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;

/// Start a TPM authorization session and save the session context to a file.
///
/// The session can later be used for policy evaluation or HMAC-based
/// authorization in other commands.
#[derive(Parser)]
pub struct StartAuthSessionCmd {
    /// Output file for the session context
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Hash algorithm for the session (sha1, sha256, sha384, sha512)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Start a policy session (instead of the default trial session)
    #[arg(long = "policy-session", conflicts_with_all = ["hmac-session", "audit-session"])]
    pub policy_session: bool,

    /// Start an HMAC session
    #[arg(long = "hmac-session", conflicts_with_all = ["policy-session", "audit-session"])]
    pub hmac_session: bool,

    /// Start an audit session (HMAC with audit flag)
    #[arg(long = "audit-session", conflicts_with_all = ["policy-session", "hmac-session"])]
    pub audit_session: bool,
}

impl StartAuthSessionCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let session_type = self.resolve_session_type();

        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                session_type,
                SymmetricDefinition::AES_128_CFB,
                hash_alg,
            )
            .context("TPM2_StartAuthSession failed")?
            .ok_or_else(|| anyhow::anyhow!("no session returned"))?;

        // Set the audit attribute if --audit-session was requested.
        if self.audit_session {
            let (attrs, mask) = SessionAttributesBuilder::new().with_audit(true).build();
            ctx.tr_sess_set_attributes(session, attrs, mask)
                .context("failed to set audit attribute on session")?;
        }

        // Save the session context to file.
        let session_handle: SessionHandle = session.into();
        let handle: tss_esapi::handles::ObjectHandle = session_handle.into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        info!(
            "session ({session_type:?}) saved to {}",
            self.session.display()
        );
        Ok(())
    }

    fn resolve_session_type(&self) -> SessionType {
        if self.policy_session {
            SessionType::Policy
        } else if self.hmac_session || self.audit_session {
            SessionType::Hmac
        } else {
            SessionType::Trial
        }
    }
}
