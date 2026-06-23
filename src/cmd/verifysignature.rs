// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{Digest, MaxBuffer, Public, Signature};
use tss_esapi::traits::UnMarshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
#[derive(Parser)]
#[command(
    group(
        ArgGroup::new("key_source")
            .required(true)
            .multiple(false)
            .args(["context", "key_file"])
    ),
    group(
        ArgGroup::new("signed_input")
            .required(true)
            .multiple(false)
            .args(["message", "digest"])
    )
)]
pub struct VerifySignatureCmd {
    /// Key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: Option<ContextSource>,

    /// External public key file (marshaled TPM2B_PUBLIC binary)
    #[arg(short = 'k', long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Hierarchy for the ticket (owner, endorsement, platform, null)
    #[arg(short = 'C', long = "hierarchy", default_value = "owner", value_parser = parse::parse_hierarchy)]
    pub hierarchy: Hierarchy,

    /// Hash algorithm
    #[arg(
        short = 'g',
        long = "hash-algorithm",
        default_value = "sha256",
        value_parser = parse::parse_hashing_algorithm
    )]
    pub hash_algorithm: HashingAlgorithm,

    /// File containing the message that was signed
    #[arg(short = 'm', long = "message")]
    pub message: Option<PathBuf>,

    /// File containing the digest that was signed
    #[arg(short = 'd', long = "digest")]
    pub digest: Option<PathBuf>,

    /// File containing the signature to verify (raw TPM marshaled binary)
    #[arg(short = 's', long = "signature")]
    pub signature: PathBuf,

    /// Output file for the verification ticket
    #[arg(short = 't', long = "ticket")]
    pub ticket: Option<PathBuf>,
}

impl VerifySignatureCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let (key_handle, flush_after) = if let Some(ref key_path) = self.key_file {
            let handle = load_external_public_key(&mut ctx, key_path, self.hierarchy)?;
            (handle, true)
        } else {
            let src = self
                .context
                .as_ref()
                .expect("clap requires exactly one key source");
            let handle = load_key_from_source(&mut ctx, src)?;
            (handle, false)
        };

        let digest_bytes = if let Some(digest_path) = &self.digest {
            std::fs::read(digest_path)
                .with_context(|| format!("reading digest: {}", digest_path.display()))?
        } else {
            let message_path = self
                .message
                .as_ref()
                .expect("clap requires exactly one signed input");
            let message_bytes = std::fs::read(message_path)
                .with_context(|| format!("reading message: {}", message_path.display()))?;
            let alg = self.hash_algorithm;
            let buffer = MaxBuffer::try_from(message_bytes)
                .map_err(|e| anyhow::anyhow!("input too large: {e}"))?;
            let (digest, _ticket) = ctx
                .execute_without_session(|ctx| ctx.hash(buffer.clone(), alg, self.hierarchy))
                .context("TPM2_Hash failed")?;
            digest.as_bytes().to_vec()
        };

        let digest =
            Digest::try_from(digest_bytes).map_err(|e| anyhow::anyhow!("invalid digest: {e}"))?;

        let sig_bytes = std::fs::read(&self.signature)
            .with_context(|| format!("reading signature: {}", self.signature.display()))?;
        let signature = Signature::unmarshall(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse signature: {e}"))?;

        let _ticket = ctx
            .execute_without_session(|ctx| {
                ctx.verify_signature(key_handle, digest.clone(), signature.clone())
            })
            .context("TPM2_VerifySignature failed")?;

        info!("signature is valid");

        if let Some(ref path) = self.ticket {
            let bytes = crate::ticket::marshall_ticket(&_ticket);
            std::fs::write(path, bytes)?;
            info!("ticket saved to {}", path.display());
        }
        if flush_after {
            ctx.flush_context(key_handle.into())
                .context("failed to flush external key handle")?;
        }

        Ok(())
    }
}

/// Load an external public key from a marshaled TPM2B_PUBLIC file into the TPM.
fn load_external_public_key(
    ctx: &mut tss_esapi::Context,
    path: &PathBuf,
    hierarchy: Hierarchy,
) -> anyhow::Result<tss_esapi::handles::KeyHandle> {
    let pub_data = std::fs::read(path)
        .with_context(|| format!("reading public key file: {}", path.display()))?;
    let public = Public::unmarshall(&pub_data)
        .map_err(|e| anyhow::anyhow!("failed to unmarshal public key: {e}"))?;
    let key_handle = ctx
        .execute_without_session(|ctx| ctx.load_external(None, public, hierarchy))
        .context("TPM2_LoadExternal (public only) failed")?;
    info!("loaded external public key from {}", path.display());
    Ok(key_handle)
}
