// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::SessionHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::SymmetricDefinition;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};

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
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Start a policy session (instead of the default trial session)
    #[arg(long = "policy-session", conflicts_with_all = ["hmac_session", "audit_session"])]
    pub policy_session: bool,

    /// Start an HMAC session
    #[arg(long = "hmac-session", conflicts_with_all = ["policy_session", "audit_session"])]
    pub hmac_session: bool,

    /// Start an audit session (HMAC with audit flag)
    #[arg(long = "audit-session", conflicts_with_all = ["policy_session", "hmac_session"])]
    pub audit_session: bool,

    /// Symmetric algorithm for session encryption (aes128cfb, aes256cfb, xor, null)
    #[arg(long = "symmetric", default_value = "aes128cfb", value_parser = parse::parse_symmetric_definition)]
    pub symmetric: SymmetricDefinition,

    /// Bind the session to a loaded object (file:<path> or hex:<handle>)
    #[arg(long = "bind", value_parser = parse_context_source)]
    pub bind: Option<ContextSource>,

    /// Enable parameter encryption (encrypt flag on session)
    #[arg(long = "enable-encrypt")]
    pub enable_encrypt: bool,

    /// Enable parameter decryption (decrypt flag on session)
    #[arg(long = "enable-decrypt")]
    pub enable_decrypt: bool,
}

impl StartAuthSessionCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session_type = self.resolve_session_type();

        let bind_handle = match &self.bind {
            Some(src) => Some(load_object_from_source(&mut ctx, src)?),
            None => None,
        };

        let session = ctx
            .start_auth_session(
                None,
                bind_handle,
                None,
                session_type,
                self.symmetric,
                self.hash_algorithm,
            )
            .context("TPM2_StartAuthSession failed")?
            .ok_or_else(|| anyhow::anyhow!("no session returned"))?;

        // Set session attributes if requested.
        if self.audit_session || self.enable_encrypt || self.enable_decrypt {
            let mut builder = SessionAttributesBuilder::new();
            if self.audit_session {
                builder = builder.with_audit(true);
            }
            if self.enable_encrypt {
                builder = builder.with_encrypt(true);
            }
            if self.enable_decrypt {
                builder = builder.with_decrypt(true);
            }
            let (attrs, mask) = builder.build();
            ctx.tr_sess_set_attributes(session, attrs, mask)
                .context("failed to set session attributes")?;
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
