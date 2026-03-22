// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{AuthHandle, ObjectHandle, SessionHandle};
use tss_esapi::interface_types::session_handles::AuthSession;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::load_session_from_file;

/// Couple a policy to the authorization of another object.
///
/// Extends the policy session with TPM2_PolicySecret, binding it to
/// the authorization of the object specified by `-c`.
#[derive(Parser)]
pub struct PolicySecretCmd {
    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "object-context", value_parser = parse_context_source, conflicts_with = "object_context_hierarchy")]
    pub object_context: Option<ContextSource>,

    /// Hierarchy shorthand (o/owner, e/endorsement, p/platform, l/lockout)
    #[arg(long = "object-hierarchy", value_parser = parse::parse_auth_handle, conflicts_with = "object_context")]
    pub object_context_hierarchy: Option<AuthHandle>,

    /// Policy session file (from tpm2 startauthsession)
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,

    /// Authorization value for the object
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,
}

impl PolicySecretCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        // Load the policy session.
        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        // Resolve the auth entity.  Accept hierarchy shorthands first,
        // then fall back to loading a generic object handle.
        let auth_handle = match self.object_context_hierarchy {
            Some(ah) => ah,
            None => {
                let src = self.object_context.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--object-context or --object-hierarchy is required")
                })?;
                let obj = load_object_from_source(&mut ctx, src)?;
                // Set the auth value on the object if provided.
                if let Some(ref auth_str) = self.auth {
                    let auth = parse::parse_auth(auth_str)?;
                    ctx.tr_set_auth(obj, auth).context("tr_set_auth failed")?;
                }
                AuthHandle::from(obj)
            }
        };

        // For hierarchy handles, set auth directly if supplied.
        if let Some(ref auth_str) = self.auth {
            match auth_handle {
                AuthHandle::Owner
                | AuthHandle::Endorsement
                | AuthHandle::Platform
                | AuthHandle::Lockout => {
                    let auth = parse::parse_auth(auth_str)?;
                    ctx.tr_set_auth(auth_handle.into(), auth)
                        .context("tr_set_auth failed")?;
                }
                _ => {} // already handled above
            }
        }

        // Execute PolicySecret with a password session for the auth entity.
        ctx.set_sessions((Some(AuthSession::Password), None, None));
        let (_timeout, _ticket) = ctx
            .policy_secret(
                policy_session,
                auth_handle,
                Default::default(), // nonce_tpm
                Default::default(), // cp_hash_a
                Default::default(), // policy_ref
                None,               // expiration
            )
            .context("TPM2_PolicySecret failed")?;
        ctx.clear_sessions();

        info!("policy secret satisfied");

        // Optionally save the policy digest.
        if let Some(ref path) = self.policy {
            let digest = ctx
                .policy_get_digest(policy_session)
                .context("TPM2_PolicyGetDigest failed")?;
            std::fs::write(path, digest.value())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
            info!("policy digest saved to {}", path.display());
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        info!("session saved to {}", self.session.display());
        Ok(())
    }
}
