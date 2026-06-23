// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{AuthHandle, ObjectHandle, SessionHandle};
use tss_esapi::structures::{Auth, Digest, Nonce, SensitiveData};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::{load_optional_auth_session, load_session_from_file};
#[derive(Parser)]
#[command(group(
    ArgGroup::new("auth_object")
        .required(true)
        .multiple(false)
        .args(["object_context", "object_context_hierarchy"])
))]
pub struct PolicySecretCmd {
    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "object-context", value_parser = parse_context_source)]
    pub object_context: Option<ContextSource>,

    /// Hierarchy shorthand (o/owner, e/endorsement, p/platform, l/lockout)
    #[arg(long = "object-hierarchy", value_parser = parse::parse_auth_handle)]
    pub object_context_hierarchy: Option<AuthHandle>,

    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,

    /// Authorization value for the object
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Nonce TPM value (hex:<hex> or file:<path>)
    #[arg(long = "nonce", value_parser = parse::parse_sensitive_data)]
    pub nonce: Option<SensitiveData>,

    /// CP hash value (hex:<hex> or file:<path>)
    #[arg(long = "cp-hash", value_parser = parse::parse_sensitive_data)]
    pub cp_hash: Option<SensitiveData>,

    /// Policy reference value (hex:<hex> or file:<path>)
    #[arg(long = "policy-ref", value_parser = parse::parse_sensitive_data)]
    pub policy_ref: Option<SensitiveData>,

    /// Expiration timeout in seconds (0 for no expiration)
    #[arg(short = 'x', long = "expiration")]
    pub expiration: Option<i32>,

    /// Output file for the timeout value
    #[arg(short = 't', long = "timeout")]
    pub timeout_out: Option<PathBuf>,

    /// Output file for the policy ticket
    #[arg(long = "ticket")]
    pub ticket_out: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(long = "auth-session")]
    pub auth_session: Option<PathBuf>,
}

impl PolicySecretCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;
        let auth_handle = match self.object_context_hierarchy {
            Some(ah) => ah,
            None => {
                let src = self
                    .object_context
                    .as_ref()
                    .expect("clap requires exactly one authorization object");
                let obj = load_object_from_source(&mut ctx, src)?;
                if let Some(ref auth) = self.auth {
                    ctx.tr_set_auth(obj, auth.clone())
                        .context("tr_set_auth failed")?;
                }
                AuthHandle::from(obj)
            }
        };
        if let Some(ref auth) = self.auth {
            match auth_handle {
                AuthHandle::Owner
                | AuthHandle::Endorsement
                | AuthHandle::Platform
                | AuthHandle::Lockout => {
                    ctx.tr_set_auth(auth_handle.into(), auth.clone())
                        .context("tr_set_auth failed")?;
                }
                _ => {}
            }
        }
        let nonce_tpm = match &self.nonce {
            Some(data) => Nonce::try_from(data.as_bytes().to_vec())
                .map_err(|e| anyhow::anyhow!("invalid nonce: {e}"))?,
            None => Default::default(),
        };

        let cp_hash_a = match &self.cp_hash {
            Some(data) => Digest::try_from(data.as_bytes().to_vec())
                .map_err(|e| anyhow::anyhow!("invalid cp-hash: {e}"))?,
            None => Default::default(),
        };

        let policy_ref = match &self.policy_ref {
            Some(data) => Nonce::try_from(data.as_bytes().to_vec())
                .map_err(|e| anyhow::anyhow!("invalid policy-ref: {e}"))?,
            None => Default::default(),
        };

        let expiration = self.expiration.and_then(|secs| {
            if secs > 0 {
                Some(Duration::from_secs(secs as u64))
            } else {
                None
            }
        });
        let auth_session = load_optional_auth_session(&mut ctx, self.auth_session.as_deref())?;
        ctx.set_sessions((Some(auth_session), None, None));
        let (timeout, ticket) = ctx
            .policy_secret(
                policy_session,
                auth_handle,
                nonce_tpm,
                cp_hash_a,
                policy_ref,
                expiration,
            )
            .context("TPM2_PolicySecret failed")?;
        ctx.clear_sessions();

        info!("policy secret satisfied");
        if let Some(ref path) = self.timeout_out {
            std::fs::write(path, timeout.as_bytes())
                .with_context(|| format!("writing timeout to {}", path.display()))?;
            info!("timeout saved to {}", path.display());
        }
        if let Some(ref path) = self.ticket_out {
            let bytes = crate::ticket::marshall_ticket(&ticket);
            std::fs::write(path, bytes)
                .with_context(|| format!("writing ticket to {}", path.display()))?;
            info!("ticket saved to {}", path.display());
        }
        if let Some(ref path) = self.policy {
            let digest = ctx
                .policy_get_digest(policy_session)
                .context("TPM2_PolicyGetDigest failed")?;
            std::fs::write(path, digest.as_bytes())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
            info!("policy digest saved to {}", path.display());
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        info!("session saved to {}", self.session.display());
        Ok(())
    }
}
