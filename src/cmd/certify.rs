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
use crate::parse;
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Certify that an object is loaded in the TPM.
///
/// Wraps TPM2_Certify: the signing key produces a signed attestation
/// structure proving that the certified object is loaded and
/// self-consistent.
#[derive(Parser)]
pub struct CertifyCmd {
    /// Object to certify (context file path)
    #[arg(
        short = 'c',
        long = "certifiedkey-context",
        conflicts_with = "certified_context_handle"
    )]
    pub certified_context: Option<PathBuf>,

    /// Object to certify (hex handle, e.g. 0x81000001)
    #[arg(long = "certifiedkey-context-handle", value_parser = parse_hex_u32, conflicts_with = "certified_context")]
    pub certified_context_handle: Option<u32>,

    /// Signing key context file path
    #[arg(
        short = 'C',
        long = "signingkey-context",
        conflicts_with = "signing_context_handle"
    )]
    pub signing_context: Option<PathBuf>,

    /// Signing key handle (hex, e.g. 0x81000001)
    #[arg(long = "signingkey-context-handle", value_parser = parse_hex_u32, conflicts_with = "signing_context")]
    pub signing_context_handle: Option<u32>,

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

    /// Qualifying data (hex string)
    #[arg(
        short = 'q',
        long = "qualification",
        conflicts_with = "qualification_file"
    )]
    pub qualification: Option<String>,

    /// Qualifying data file path
    #[arg(long = "qualification-file", conflicts_with = "qualification")]
    pub qualification_file: Option<PathBuf>,

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
    fn certified_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.certified_context, self.certified_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --certifiedkey-context or --certifiedkey-context-handle must be provided"
            ),
        }
    }

    fn signing_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.signing_context, self.signing_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --signingkey-context or --signingkey-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let object_handle = load_object_from_source(&mut ctx, &self.certified_context_source()?)?;
        let signing_key = load_key_from_source(&mut ctx, &self.signing_context_source()?)?;
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

        let qualifying = match (&self.qualification, &self.qualification_file) {
            (Some(q), None) => {
                let bytes =
                    parse::parse_qualification_hex(q).context("failed to parse qualifying data")?;
                Data::try_from(bytes).map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
            }
            (None, Some(path)) => {
                let bytes = parse::parse_qualification_file(path)
                    .context("failed to read qualifying data file")?;
                Data::try_from(bytes).map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
            }
            (None, None) => Data::default(),
            _ => {
                anyhow::bail!("only one of --qualification or --qualification-file may be provided")
            }
        };

        let session_path = self.session.as_deref();
        let (attest, signature) = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.certify(object_handle, signing_key, qualifying.clone(), scheme)
        })
        .context("TPM2_Certify failed")?;

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
