// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{Digest, MaxBuffer, Public, Signature};
use tss_esapi::traits::UnMarshall;
use tss_esapi::tss2_esys::TPMT_TK_VERIFIED;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};

/// Verify a signature using a TPM-loaded key or an external public key file.
///
/// The signature file should contain a raw TPM marshaled TPMT_SIGNATURE.
/// The verification key can be specified as a context source (`-c file:<path>`
/// or `-c hex:<handle>`), or an external public key file (`-k`) in
/// marshaled TPM2B_PUBLIC format.
#[derive(Parser)]
pub struct VerifySignatureCmd {
    /// Key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source, conflicts_with = "key_file")]
    pub context: Option<ContextSource>,

    /// External public key file (marshaled TPM2B_PUBLIC binary)
    #[arg(short = 'k', long = "key-file", conflicts_with = "context")]
    pub key_file: Option<PathBuf>,

    /// Hierarchy for the ticket (owner, endorsement, platform, null)
    #[arg(short = 'C', long = "hierarchy", default_value = "owner", value_parser = parse::parse_hierarchy)]
    pub hierarchy: Hierarchy,

    /// Hash algorithm (sha1, sha256, sha384, sha512)
    #[arg(
        short = 'g',
        long = "hash-algorithm",
        default_value = "sha256",
        requires = "message",
        conflicts_with = "digest"
    )]
    pub hash_algorithm: Option<String>,

    /// File containing the message that was signed
    #[arg(
        short = 'm',
        long = "message",
        conflicts_with = "digest",
        requires = "hash-algorithm",
        conflicts_with = "digest"
    )]
    pub message: Option<PathBuf>,

    /// File containing the digest that was signed
    #[arg(short = 'd', long = "digest", conflicts_with_all = ["message", "hash-algorithm"])]
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
        let mut ctx = create_context(global.tcti.as_deref())?;

        // Resolve the verification key: context source or external key file.
        let (key_handle, flush_after) = if let Some(ref key_path) = self.key_file {
            let handle = load_external_public_key(&mut ctx, key_path, self.hierarchy)?;
            (handle, true)
        } else {
            let src = self.context.as_ref().ok_or_else(|| {
                anyhow::anyhow!("exactly one of --context or --key-file must be provided")
            })?;
            let handle = load_key_from_source(&mut ctx, src)?;
            (handle, false)
        };

        let digest_bytes = if let Some(digest_path) = &self.digest {
            std::fs::read(digest_path)
                .with_context(|| format!("reading digest: {}", digest_path.display()))?
        } else {
            let message_path = self.message.as_ref().unwrap();
            let message_bytes = std::fs::read(message_path)
                .with_context(|| format!("reading message: {}", message_path.display()))?;
            let hash_alg_str = self.hash_algorithm.as_ref().unwrap();
            let alg = parse::parse_hashing_algorithm(hash_alg_str)
                .with_context(|| "failed to parse hash algorithm")?;
            let buffer = MaxBuffer::try_from(message_bytes)
                .map_err(|e| anyhow::anyhow!("input too large: {e}"))?;
            let (digest, _ticket) = ctx
                .execute_without_session(|ctx| ctx.hash(buffer.clone(), alg, self.hierarchy))
                .context("TPM2_Hash failed")?;
            digest.value().to_vec()
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
            let tss_ticket: TPMT_TK_VERIFIED = _ticket
                .try_into()
                .map_err(|e| anyhow::anyhow!("failed to convert ticket: {e}"))?;
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &tss_ticket as *const TPMT_TK_VERIFIED as *const u8,
                    std::mem::size_of::<TPMT_TK_VERIFIED>(),
                )
            };
            std::fs::write(path, bytes)?;
            info!("ticket saved to {}", path.display());
        }

        // Flush the transient handle if we loaded an external key.
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
        .execute_without_session(|ctx| ctx.load_external_public(public, hierarchy))
        .context("TPM2_LoadExternal (public only) failed")?;
    info!("loaded external public key from {}", path.display());
    Ok(key_handle)
}
