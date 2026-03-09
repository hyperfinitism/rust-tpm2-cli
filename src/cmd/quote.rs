use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Data;
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_hex_u32};
use crate::pcr;
use crate::session::execute_with_optional_session;

/// Generate a TPM quote over selected PCRs.
#[derive(Parser)]
pub struct QuoteCmd {
    /// Signing key context file path
    #[arg(short = 'c', long = "context", conflicts_with = "context_handle")]
    pub context: Option<PathBuf>,

    /// Signing key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "context-handle", value_parser = parse_hex_u32, conflicts_with = "context")]
    pub context_handle: Option<u32>,

    /// PCR selection list (e.g. sha256:0,1,2+sha1:all)
    #[arg(short = 'l', long = "pcr-list")]
    pub pcr_list: String,

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
    fn context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.context, self.context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!("exactly one of --context or --context-handle must be provided"),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context_source()?)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let scheme = parse::parse_signature_scheme(&self.scheme, hash_alg)?;
        let pcr_selection = parse::parse_pcr_selection(&self.pcr_list)?;

        let qualifying_data = if let Some(ref q) = self.qualification {
            let bytes =
                parse::parse_qualification_hex(q).context("failed to parse qualification data")?;
            Data::try_from(bytes).map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
        } else if let Some(ref path) = self.qualification_file {
            let bytes = parse::parse_qualification_file(path)
                .context("failed to read qualification file")?;
            Data::try_from(bytes).map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
        } else {
            Data::default()
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
                    raw.extend_from_slice(digest.value());
                }
            }
            std::fs::write(path, &raw)
                .with_context(|| format!("writing PCR data to {}", path.display()))?;
            info!("PCR data saved to {}", path.display());
        }

        Ok(())
    }
}
