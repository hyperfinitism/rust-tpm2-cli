use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::tss::TPM2_RH_NULL;
use tss_esapi::structures::{Digest, HashcheckTicket};
use tss_esapi::traits::Marshall;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::{self, parse_hex_u32};
use crate::session::execute_with_optional_session;

/// Sign a digest with a TPM key.
#[derive(Parser)]
pub struct SignCmd {
    /// Signing key context file path
    #[arg(short = 'c', long = "context", conflicts_with = "context_handle")]
    pub context: Option<PathBuf>,

    /// Signing key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "context-handle", value_parser = parse_hex_u32, conflicts_with = "context")]
    pub context_handle: Option<u32>,

    /// Hash algorithm (sha1, sha256, sha384, sha512)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Signature scheme (rsassa, rsapss, ecdsa)
    #[arg(short = 's', long = "scheme", default_value = "rsassa")]
    pub scheme: String,

    /// File containing the digest to sign
    #[arg(short = 'd', long = "digest")]
    pub digest: PathBuf,

    /// Output file for the signature
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Hashcheck ticket file from tpm2 hash (required for restricted keys)
    #[arg(short = 't', long = "ticket")]
    pub ticket: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl SignCmd {
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

        let digest_bytes = std::fs::read(&self.digest)
            .with_context(|| format!("reading digest: {}", self.digest.display()))?;
        let digest =
            Digest::try_from(digest_bytes).map_err(|e| anyhow::anyhow!("invalid digest: {e}"))?;

        let validation = if let Some(ref ticket_path) = self.ticket {
            let ticket_data = std::fs::read(ticket_path)
                .with_context(|| format!("reading ticket from {}", ticket_path.display()))?;
            if ticket_data.len() < std::mem::size_of::<TPMT_TK_HASHCHECK>() {
                anyhow::bail!("ticket file too small");
            }
            let tss_ticket: TPMT_TK_HASHCHECK =
                unsafe { std::ptr::read(ticket_data.as_ptr() as *const TPMT_TK_HASHCHECK) };
            HashcheckTicket::try_from(tss_ticket)
                .map_err(|e| anyhow::anyhow!("invalid ticket: {e}"))?
        } else {
            // Null ticket for externally-provided digests (unrestricted keys only)
            HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
                tag: tss_esapi::constants::StructureTag::Hashcheck.into(),
                hierarchy: TPM2_RH_NULL,
                digest: Default::default(),
            })
            .map_err(|e| anyhow::anyhow!("failed to create hashcheck ticket: {e}"))?
        };

        let session_path = self.session.as_deref();
        let signature = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.sign(key_handle, digest.clone(), scheme, validation.clone())
        })
        .context("TPM2_Sign failed")?;

        let sig_bytes = signature
            .marshall()
            .context("failed to marshal TPMT_SIGNATURE")?;

        if let Some(ref path) = self.output {
            std::fs::write(path, &sig_bytes)?;
            info!("signature saved to {}", path.display());
        } else {
            output::print_hex(&sig_bytes);
        }

        Ok(())
    }
}
