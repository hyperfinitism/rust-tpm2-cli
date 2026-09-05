// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Digest, HashcheckTicket};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct SignCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Authorization value for the signing key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Hash algorithm
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Signature scheme (rsassa, rsapss, ecdsa)
    #[arg(short = 's', long = "scheme", default_value = "rsassa", value_parser = parse::parse_signature_scheme_kind)]
    pub scheme: parse::SignatureSchemeKind,

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
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context)?;
        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(key_handle.into(), auth.clone())
                .context("failed to set signing key authorization")?;
        }
        let scheme = self.scheme.with_hash(self.hash_algorithm);

        let digest_bytes = std::fs::read(&self.digest)
            .with_context(|| format!("reading digest: {}", self.digest.display()))?;
        let digest =
            Digest::try_from(digest_bytes).map_err(|e| anyhow::anyhow!("invalid digest: {e}"))?;

        let validation = if let Some(ref ticket_path) = self.ticket {
            let ticket_data = std::fs::read(ticket_path)
                .with_context(|| format!("reading ticket from {}", ticket_path.display()))?;
            crate::ticket::parse_hashcheck_ticket(&ticket_data)?
        } else {
            HashcheckTicket::default()
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
