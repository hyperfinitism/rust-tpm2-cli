// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

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
use crate::parse::{parse_context_source, parse_duration};
use crate::session::load_session_from_file;

/// Authorize a policy with a signed authorization.
///
/// Wraps TPM2_PolicySigned.
#[derive(Parser)]
pub struct PolicySignedCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Signature file (marshaled TPMT_SIGNATURE)
    #[arg(short = 's', long = "signature")]
    pub signature: PathBuf,

    /// Expiration time in seconds (0 = no expiration)
    #[arg(short = 'x', long = "expiration", value_parser = parse_duration, default_value = None)]
    pub expiration: Option<Duration>,

    /// cpHash file (optional)
    #[arg(long = "cphash-input")]
    pub cphash_input: Option<PathBuf>,

    /// Policy reference (digest) (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = crate::parse::parse_qualification)]
    pub qualification: Option<crate::parse::Qualification>,

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
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let auth_object = load_object_from_source(&mut ctx, &self.key_context)?;

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
            Some(bytes) => Nonce::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Nonce::default(),
        };

        let (timeout, ticket) = ctx
            .policy_signed(
                policy_session,
                auth_object,
                Nonce::default(), // nonce_tpm
                cp_hash,
                policy_ref,
                self.expiration,
                signature,
            )
            .context("TPM2_PolicySigned failed")?;

        info!("policy signed succeeded");

        if let Some(ref path) = self.timeout_out {
            std::fs::write(path, timeout.as_bytes())
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
            std::fs::write(path, digest.as_bytes())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        Ok(())
    }
}
