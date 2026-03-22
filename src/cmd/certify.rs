// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Data;
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::load_session_from_file;
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::session_handles::AuthSession;

/// Certify that an object is loaded in the TPM.
///
/// Wraps TPM2_Certify: the signing key produces a signed attestation
/// structure proving that the certified object is loaded and
/// self-consistent.
#[derive(Parser)]
pub struct CertifyCmd {
    /// Object to certify (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "certifiedkey-context", value_parser = parse_context_source)]
    pub certified_context: ContextSource,

    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "signingkey-context", value_parser = parse_context_source)]
    pub signing_context: ContextSource,

    /// Auth value for the certified object
    #[arg(short = 'P', long = "certifiedkey-auth")]
    pub certified_auth: Option<String>,

    /// Auth value for the signing key
    #[arg(short = 'p', long = "signingkey-auth")]
    pub signing_auth: Option<String>,

    /// Hash algorithm for signing
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null")]
    pub scheme: String,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Output file for the attestation data (marshaled TPMS_ATTEST)
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature (marshaled TPMT_SIGNATURE)
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl CertifyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let object_handle = load_object_from_source(&mut ctx, &self.certified_context)?;
        let signing_key = load_key_from_source(&mut ctx, &self.signing_context)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let scheme = parse::parse_signature_scheme(&self.scheme, hash_alg)?;

        if let Some(ref auth_str) = self.certified_auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(object_handle, auth)
                .context("failed to set certified key auth")?;
        }
        if let Some(ref auth_str) = self.signing_auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(signing_key.into(), auth)
                .context("failed to set signing key auth")?;
        }

        let qualifying = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };

        // TPM2_Certify requires two auth sessions: one for the certified
        // object (authSession1) and one for the signing key (authSession2).
        // If -S is provided, use it for the certified object; otherwise
        // fall back to password auth.  The signing key always uses password.
        let session1 = match &self.session {
            Some(path) => load_session_from_file(&mut ctx, path, SessionType::Hmac)?,
            None => AuthSession::Password,
        };
        ctx.set_sessions((Some(session1), Some(AuthSession::Password), None));
        let result = ctx
            .certify(object_handle, signing_key, qualifying.clone(), scheme)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (attest, signature) = result.context("TPM2_Certify failed")?;

        if let Some(ref path) = self.attestation {
            let bytes = attest.marshall().context("failed to marshal TPMS_ATTEST")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing attestation to {}", path.display()))?;
            info!("attestation saved to {}", path.display());
        }

        if let Some(ref path) = self.signature {
            let bytes = signature
                .marshall()
                .context("failed to marshal TPMT_SIGNATURE")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing signature to {}", path.display()))?;
            info!("signature saved to {}", path.display());
        }

        info!("certify succeeded");
        Ok(())
    }
}
