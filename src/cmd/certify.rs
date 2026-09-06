// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Data};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::{
    load_optional_auth_session, load_optional_policy_or_hmac_session, save_session_to_file,
};
#[derive(Parser)]
pub struct CertifyCmd {
    /// Object to certify (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "certifiedkey-context", value_parser = parse_context_source)]
    pub certified_context: ContextSource,

    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "signingkey-context", value_parser = parse_context_source)]
    pub signing_context: ContextSource,

    /// Authorization value for the certified object
    #[arg(short = 'P', long = "certifiedkey-auth", value_parser = parse::parse_auth)]
    pub certified_auth: Option<Auth>,

    /// Authorization value for the signing key
    #[arg(short = 'p', long = "signingkey-auth", value_parser = parse::parse_auth)]
    pub signing_auth: Option<Auth>,

    /// Hash algorithm for signing
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null", value_parser = parse::parse_signature_scheme_kind)]
    pub scheme: parse::SignatureSchemeKind,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Output file for the attestation data (marshaled TPMS_ATTEST)
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature (marshaled TPMT_SIGNATURE)
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,

    /// HMAC session context file for certified object authorization
    #[arg(short = 'S', long = "session", conflicts_with = "policy_session")]
    pub session: Option<PathBuf>,

    /// Policy session context file for certified object authorization
    #[arg(long = "policy-session", conflicts_with = "session")]
    pub policy_session: Option<PathBuf>,

    /// Session context file for signing key authorization
    #[arg(long = "signing-session")]
    pub signing_session: Option<PathBuf>,
}

impl CertifyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let object_handle = load_object_from_source(&mut ctx, &self.certified_context)?;
        let signing_key = load_key_from_source(&mut ctx, &self.signing_context)?;
        let scheme = self.scheme.with_hash(self.hash_algorithm);

        if let Some(ref auth) = self.certified_auth {
            ctx.tr_set_auth(object_handle, auth.clone())
                .context("failed to set certified key auth")?;
        }
        if let Some(ref auth) = self.signing_auth {
            ctx.tr_set_auth(signing_key.into(), auth.clone())
                .context("failed to set signing key auth")?;
        }

        let qualifying = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };
        let object_session = load_optional_policy_or_hmac_session(
            &mut ctx,
            self.policy_session.as_deref(),
            self.session.as_deref(),
        )?;
        let signing_session =
            load_optional_auth_session(&mut ctx, self.signing_session.as_deref())?;
        ctx.set_sessions((Some(object_session), Some(signing_session), None));
        let result = ctx
            .certify(object_handle, signing_key, qualifying.clone(), scheme)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (attest, signature) = result.context("TPM2_Certify failed")?;

        if let Some(path) = self.policy_session.as_deref().or(self.session.as_deref()) {
            save_session_to_file(&mut ctx, object_session, path)?;
        }
        if let Some(path) = self.signing_session.as_deref() {
            save_session_to_file(&mut ctx, signing_session, path)?;
        }

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
