// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Data;
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse;
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Get a signed timestamp from the TPM.
///
/// Wraps TPM2_GetTime: produces an attestation structure containing
/// the current time and clock values, signed by the specified key.
#[derive(Parser)]
pub struct GetTimeCmd {
    /// Signing key context file path
    #[arg(short = 'c', long = "context", conflicts_with = "context_handle")]
    pub context: Option<PathBuf>,

    /// Signing key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "context-handle", value_parser = parse_hex_u32, conflicts_with = "context")]
    pub context_handle: Option<u32>,

    /// Auth value for the signing key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

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
    fn context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.context, self.context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!("exactly one of --context or --context-handle must be provided"),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let signing_key = load_key_from_source(&mut ctx, &self.context_source()?)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let scheme = parse::parse_signature_scheme(&self.scheme, hash_alg)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(signing_key.into(), auth)
                .context("tr_set_auth failed")?;
        }

        let qualifying = match (&self.qualification, &self.qualification_file) {
            (Some(q), None) => {
                let bytes = parse::parse_qualification_hex(q)?;
                Data::try_from(bytes).map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
            }
            (None, Some(path)) => {
                let bytes = parse::parse_qualification_file(path)?;
                Data::try_from(bytes).map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
            }
            _ => Data::default(),
        };

        let session_path = self.session.as_deref();
        let (attest, signature) = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.get_time(signing_key, qualifying.clone(), scheme)
        })
        .context("TPM2_GetTime failed")?;

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
