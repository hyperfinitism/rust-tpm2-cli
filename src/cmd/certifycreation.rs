// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::session::execute_with_optional_session;
use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Data, Digest};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source, load_object_from_source};
use crate::parse::{self, parse_context_source};
#[derive(Parser)]
pub struct CertifyCreationCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "signingkey-context", value_parser = parse_context_source)]
    pub signing_context: ContextSource,

    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "certifiedkey-context", value_parser = parse_context_source)]
    pub certified_context: ContextSource,

    /// Authorization value for the signing key
    #[arg(short = 'P', long = "signingkey-auth", value_parser = parse::parse_auth)]
    pub signing_auth: Option<Auth>,

    /// Creation hash file
    #[arg(short = 'd', long = "creation-hash")]
    pub creation_hash: PathBuf,

    /// Creation ticket file
    #[arg(short = 't', long = "ticket")]
    pub ticket: PathBuf,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Signature scheme (null)
    #[arg(short = 'g', long = "scheme", default_value = "null", value_parser = parse::parse_signature_scheme_kind)]
    pub scheme: parse::SignatureSchemeKind,

    /// Hash algorithm used by the signature scheme
    #[arg(long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Output file for attestation
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for signature
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl CertifyCreationCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let sign_handle = load_key_from_source(&mut ctx, &self.signing_context)?;
        let obj_handle = load_object_from_source(&mut ctx, &self.certified_context)?;

        if let Some(ref auth) = self.signing_auth {
            ctx.tr_set_auth(sign_handle.into(), auth.clone())
                .context("failed to set signing key auth")?;
        }

        let creation_hash_data = std::fs::read(&self.creation_hash).with_context(|| {
            format!(
                "reading creation hash from {}",
                self.creation_hash.display()
            )
        })?;
        let creation_hash = Digest::try_from(creation_hash_data)
            .map_err(|e| anyhow::anyhow!("creation hash: {e}"))?;

        let ticket_data = std::fs::read(&self.ticket)
            .with_context(|| format!("reading ticket from {}", self.ticket.display()))?;
        let creation_ticket = crate::ticket::parse_creation_ticket(&ticket_data)?;

        let qualifying_data = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };

        let scheme = self.scheme.with_hash(self.hash_algorithm);

        let result = execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.certify_creation(
                sign_handle,
                obj_handle,
                qualifying_data.clone(),
                creation_hash.clone(),
                scheme,
                creation_ticket,
            )
        })
        .context("TPM2_CertifyCreation failed")?;
        let (attest, signature) = result;

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

        info!("certify creation succeeded");
        Ok(())
    }
}
