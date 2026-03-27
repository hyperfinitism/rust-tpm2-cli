// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Data, PcrSelectionList};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::pcr;
use crate::session::execute_with_optional_session;

/// Generate a TPM quote over selected PCRs.
#[derive(Parser)]
pub struct QuoteCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// PCR selection list (e.g. sha256:0,1,2+sha1:all)
    #[arg(short = 'l', long = "pcr-list", value_parser = parse::parse_pcr_selection)]
    pub pcr_list: PcrSelectionList,

    /// Hash algorithm for signing
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null")]
    pub scheme: String,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Output file for the quote message (TPMS_ATTEST, marshaled binary)
    #[arg(short = 'm', long = "message")]
    pub message: Option<PathBuf>,

    /// Output file for the signature (TPMT_SIGNATURE, marshaled binary)
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,

    /// Output file for PCR digest values (raw binary)
    #[arg(short = 'o', long = "pcr")]
    pub pcr_output: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl QuoteCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context)?;
        let scheme = parse::parse_signature_scheme(&self.scheme, self.hash_algorithm)
            .map_err(anyhow::Error::msg)?;
        let pcr_selection = self.pcr_list.clone();

        let qualifying_data = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };

        let session_path = self.session.as_deref();
        let (attest, signature) = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.quote(
                key_handle,
                qualifying_data.clone(),
                scheme,
                pcr_selection.clone(),
            )
        })
        .context("TPM2_Quote failed")?;

        if let Some(ref path) = self.message {
            let msg_bytes = attest.marshall().context("failed to marshal TPMS_ATTEST")?;
            std::fs::write(path, &msg_bytes)
                .with_context(|| format!("writing message to {}", path.display()))?;
            info!("message saved to {}", path.display());
        }

        if let Some(ref path) = self.signature {
            let sig_bytes = signature
                .marshall()
                .context("failed to marshal TPMT_SIGNATURE")?;
            std::fs::write(path, &sig_bytes)
                .with_context(|| format!("writing signature to {}", path.display()))?;
            info!("signature saved to {}", path.display());
        }

        if let Some(ref path) = self.pcr_output {
            let chunks = pcr::pcr_read_all(&mut ctx, pcr_selection)?;
            let mut raw = Vec::new();
            for (_, digests) in &chunks {
                for digest in digests.value() {
                    raw.extend_from_slice(digest.as_bytes());
                }
            }
            std::fs::write(path, &raw)
                .with_context(|| format!("writing PCR data to {}", path.display()))?;
            info!("PCR data saved to {}", path.display());
        }

        Ok(())
    }
}
