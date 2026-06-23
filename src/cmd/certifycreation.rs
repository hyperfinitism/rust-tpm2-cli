// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{Auth, CreationTicket, Data, Digest};
use tss_esapi::traits::Marshall;
use tss_esapi::tss2_esys::TPMT_TK_CREATION;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source, load_object_from_source};
use crate::parse::{self, parse_context_source};

/// Certify the creation data associated with an object.
///
/// Wraps TPM2_CertifyCreation (raw FFI).
#[derive(Parser)]
pub struct CertifyCreationCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "signingkey-context", value_parser = parse_context_source)]
    pub signing_context: ContextSource,

    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "certifiedkey-context", value_parser = parse_context_source)]
    pub certified_context: ContextSource,

    /// Auth value for the signing key
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
    #[arg(short = 'g', long = "scheme", default_value = "null")]
    pub scheme: String,

    /// Output file for attestation
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for signature
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,
}

impl CertifyCreationCmd {
    #[allow(clippy::field_reassign_with_default)]
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;
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
        // The ticket is a TPMT_TK_CREATION structure. For simplicity, we'll treat
        // it as raw bytes and construct the struct manually if it's the right size.
        let creation_ticket = if ticket_data.len() >= 6 {
            let mut tk = TPMT_TK_CREATION::default();
            // First 2 bytes: tag, next 4 bytes: hierarchy, rest: digest
            tk.tag = u16::from_le_bytes([ticket_data[0], ticket_data[1]]);
            tk.hierarchy = u32::from_le_bytes([
                ticket_data[2],
                ticket_data[3],
                ticket_data[4],
                ticket_data[5],
            ]);
            if ticket_data.len() > 6 {
                let digest_data = &ticket_data[6..];
                let dlen = digest_data.len().min(tk.digest.buffer.len());
                tk.digest.size = dlen as u16;
                tk.digest.buffer[..dlen].copy_from_slice(&digest_data[..dlen]);
            }
            tk
        } else {
            TPMT_TK_CREATION::default()
        };
        let creation_ticket = CreationTicket::try_from(creation_ticket)
            .map_err(|e| anyhow::anyhow!("creation ticket: {e}"))?;

        let qualifying_data = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };

        let scheme = parse::parse_signature_scheme(&self.scheme, HashingAlgorithm::Sha256)
            .map_err(anyhow::Error::msg)?;

        ctx.set_sessions((Some(AuthSession::Password), None, None));
        let result = ctx
            .certify_creation(
                sign_handle,
                obj_handle,
                qualifying_data,
                creation_hash,
                scheme,
                creation_ticket,
            )
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (attest, signature) = result.context("TPM2_CertifyCreation failed")?;

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
