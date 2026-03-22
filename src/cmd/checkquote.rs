// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::structures::{Attest, AttestInfo, MaxBuffer, Signature};
use tss_esapi::traits::UnMarshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};

/// Verify a TPM quote.
///
/// Hashes the quote message, verifies the signature with the public key,
/// and optionally checks qualification data and PCR values embedded in the
/// attestation structure.
#[derive(Parser)]
pub struct CheckQuoteCmd {
    /// Public key context (file:<path> or hex:<handle>)
    #[arg(short = 'u', long = "public", value_parser = parse_context_source)]
    pub public: ContextSource,

    /// Quote message file (marshaled TPMS_ATTEST)
    #[arg(short = 'm', long = "message")]
    pub message: PathBuf,

    /// Signature file (marshaled TPMT_SIGNATURE)
    #[arg(short = 's', long = "signature")]
    pub signature: PathBuf,

    /// Hash algorithm used to digest the message
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// PCR values file for additional verification
    #[arg(short = 'f', long = "pcr")]
    pub pcr_file: Option<PathBuf>,

    /// PCR selection list (e.g. sha256:0,1,2)
    #[arg(short = 'l', long = "pcr-list")]
    pub pcr_list: Option<String>,

    /// Qualification data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,
}

impl CheckQuoteCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.public)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;

        // ---------------------------------------------------------------
        // 1. Read and hash the quote message
        // ---------------------------------------------------------------
        let msg_bytes = std::fs::read(&self.message)
            .with_context(|| format!("reading message: {}", self.message.display()))?;

        let buffer = MaxBuffer::try_from(msg_bytes.clone())
            .map_err(|e| anyhow::anyhow!("message too large: {e}"))?;

        let (digest, _ticket) = ctx
            .execute_without_session(|ctx| {
                ctx.hash(
                    buffer,
                    hash_alg,
                    tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
                )
            })
            .context("TPM2_Hash failed")?;

        // ---------------------------------------------------------------
        // 2. Read the signature and verify against the computed digest
        // ---------------------------------------------------------------
        let sig_bytes = std::fs::read(&self.signature)
            .with_context(|| format!("reading signature: {}", self.signature.display()))?;
        let signature = Signature::unmarshall(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse signature: {e}"))?;

        ctx.execute_without_session(|ctx| {
            ctx.verify_signature(key_handle, digest.clone(), signature)
        })
        .context("TPM2_VerifySignature failed — quote signature is invalid")?;

        info!("signature verification: OK");

        // ---------------------------------------------------------------
        // 3. Unmarshal the attestation structure for further checks
        // ---------------------------------------------------------------
        let attest = Attest::unmarshall(&msg_bytes)
            .map_err(|e| anyhow::anyhow!("failed to unmarshal TPMS_ATTEST: {e}"))?;

        let quote_info = match attest.attested() {
            AttestInfo::Quote { info } => info,
            other => bail!(
                "expected a Quote attestation, got {:?}",
                std::mem::discriminant(other)
            ),
        };

        // ---------------------------------------------------------------
        // 4. Check qualification (extraData / nonce)
        // ---------------------------------------------------------------
        if let Some(ref expected) = self.qualification {
            if attest.extra_data().value() != expected.as_slice() {
                bail!(
                    "qualification mismatch: quote contains {:?}, expected {:?}",
                    hex::encode(attest.extra_data().value()),
                    hex::encode(expected.as_slice())
                );
            }
            info!("qualification check: OK");
        }

        // ---------------------------------------------------------------
        // 5. Check PCR digest
        // ---------------------------------------------------------------
        if let Some(ref pcr_path) = self.pcr_file {
            let pcr_bytes = std::fs::read(pcr_path)
                .with_context(|| format!("reading PCR file: {}", pcr_path.display()))?;

            // Hash the raw PCR values to compare with the digest in the
            // quote. Use the same algorithm that was used for the quote.
            let pcr_buf = MaxBuffer::try_from(pcr_bytes)
                .map_err(|e| anyhow::anyhow!("PCR data too large: {e}"))?;

            let (pcr_digest, _) = ctx
                .execute_without_session(|ctx| {
                    ctx.hash(
                        pcr_buf,
                        hash_alg,
                        tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
                    )
                })
                .context("TPM2_Hash of PCR values failed")?;

            let expected_pcr_digest = quote_info.pcr_digest();
            if pcr_digest.value() != expected_pcr_digest.value() {
                bail!(
                    "PCR digest mismatch: computed {}, quote contains {}",
                    hex::encode(pcr_digest.value()),
                    hex::encode(expected_pcr_digest.value())
                );
            }
            info!("PCR digest check: OK");
        }

        // ---------------------------------------------------------------
        // 6. If a PCR selection list was supplied, compare with the quote
        // ---------------------------------------------------------------
        if let Some(ref pcr_list_str) = self.pcr_list {
            let expected_selection = parse::parse_pcr_selection(pcr_list_str)?;
            let quote_selection = quote_info.pcr_selection();

            let expected_dbg = format!("{expected_selection:?}");
            let quote_dbg = format!("{quote_selection:?}");
            if expected_dbg != quote_dbg {
                bail!(
                    "PCR selection mismatch: expected {expected_dbg}, quote contains {quote_dbg}"
                );
            }
            info!("PCR selection check: OK");
        }

        info!("quote verification: OK");
        Ok(())
    }
}
