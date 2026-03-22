// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::Data;
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::load_session_from_file;

/// Get a signed timestamp from the TPM.
///
/// Wraps TPM2_GetTime: produces an attestation structure containing
/// the current time and clock values, signed by the specified key.
#[derive(Parser)]
pub struct GetTimeCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Auth value for the signing key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Hash algorithm for signing
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null")]
    pub scheme: String,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl GetTimeCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let signing_key = load_key_from_source(&mut ctx, &self.context)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let scheme = parse::parse_signature_scheme(&self.scheme, hash_alg)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(signing_key.into(), auth)
                .context("tr_set_auth failed")?;
        }

        let qualifying_data = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };

        // TPM2_GetTime requires two auth sessions: one for the privacy admin
        // (authSession1) and one for the signing key (authSession2).
        // If -S is provided, use it for the privacy admin; otherwise fall
        // back to password auth.  The signing key always uses password.
        let session1 = match &self.session {
            Some(path) => load_session_from_file(&mut ctx, path, SessionType::Hmac)?,
            None => AuthSession::Password,
        };
        ctx.set_sessions((Some(session1), Some(AuthSession::Password), None));
        let result = ctx
            .get_time(signing_key, qualifying_data.clone(), scheme)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (attest, signature) = result.context("TPM2_GetTime failed")?;

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

        info!("gettime succeeded");
        Ok(())
    }
}
