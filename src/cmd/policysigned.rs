use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::{Digest, Nonce, Signature};
use tss_esapi::traits::UnMarshall;
use tss_esapi::tss2_esys::TPMT_TK_AUTH;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::parse_hex_u32;
use crate::session::load_session_from_file;

/// Authorize a policy with a signed authorization.
///
/// Wraps TPM2_PolicySigned.
#[derive(Parser)]
pub struct PolicySignedCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Signing key context file path
    #[arg(
        short = 'c',
        long = "key-context",
        conflicts_with = "key_context_handle"
    )]
    pub key_context: Option<PathBuf>,

    /// Signing key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "key-context-handle", value_parser = parse_hex_u32, conflicts_with = "key_context")]
    pub key_context_handle: Option<u32>,

    /// Signature file (marshaled TPMT_SIGNATURE)
    #[arg(short = 's', long = "signature")]
    pub signature: PathBuf,

    /// Expiration time in seconds (0 = no expiration)
    #[arg(short = 'x', long = "expiration", default_value = "0")]
    pub expiration: i32,

    /// cpHash file (optional)
    #[arg(long = "cphash-input")]
    pub cphash_input: Option<PathBuf>,

    /// Policy reference / nonce file (optional)
    #[arg(short = 'q', long = "qualification")]
    pub qualification: Option<PathBuf>,

    /// Output file for the timeout
    #[arg(short = 't', long = "timeout")]
    pub timeout_out: Option<PathBuf>,

    /// Output file for the policy ticket
    #[arg(long = "ticket")]
    pub ticket_out: Option<PathBuf>,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicySignedCmd {
    fn key_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.key_context, self.key_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --key-context or --key-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let auth_object = load_object_from_source(&mut ctx, &self.key_context_source()?)?;

        let sig_data = std::fs::read(&self.signature)
            .with_context(|| format!("reading signature from {}", self.signature.display()))?;
        let signature = Signature::unmarshall(&sig_data)
            .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;

        let cp_hash = match &self.cphash_input {
            Some(path) => {
                let data = std::fs::read(path)?;
                Digest::try_from(data).map_err(|e| anyhow::anyhow!("invalid cpHash: {e}"))?
            }
            None => Digest::default(),
        };

        let policy_ref = match &self.qualification {
            Some(path) => {
                let data = std::fs::read(path)?;
                Nonce::try_from(data).map_err(|e| anyhow::anyhow!("invalid policy ref: {e}"))?
            }
            None => Nonce::default(),
        };

        let expiration = if self.expiration == 0 {
            None
        } else {
            Some(std::time::Duration::from_secs(self.expiration as u64))
        };

        let (timeout, ticket) = ctx
            .policy_signed(
                policy_session,
                auth_object,
                Nonce::default(), // nonce_tpm
                cp_hash,
                policy_ref,
                expiration,
                signature,
            )
            .context("TPM2_PolicySigned failed")?;

        info!("policy signed succeeded");

        if let Some(ref path) = self.timeout_out {
            std::fs::write(path, timeout.value())
                .with_context(|| format!("writing timeout to {}", path.display()))?;
        }

        if let Some(ref path) = self.ticket_out {
            let tss_ticket: TPMT_TK_AUTH = ticket
                .try_into()
                .map_err(|e| anyhow::anyhow!("failed to convert ticket: {e:?}"))?;
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &tss_ticket as *const TPMT_TK_AUTH as *const u8,
                    std::mem::size_of::<TPMT_TK_AUTH>(),
                )
            };
            std::fs::write(path, bytes)
                .with_context(|| format!("writing ticket to {}", path.display()))?;
        }

        if let Some(ref path) = self.policy {
            let digest = ctx
                .policy_get_digest(policy_session)
                .context("TPM2_PolicyGetDigest failed")?;
            std::fs::write(path, digest.value())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        Ok(())
    }
}
