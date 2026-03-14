// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{Data, PublicKeyRsa, RsaDecryptionScheme};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::parse_hex_u32;

/// Perform RSA encryption using a TPM-loaded key.
///
/// Wraps TPM2_RSA_Encrypt.
#[derive(Parser)]
pub struct RsaEncryptCmd {
    /// RSA key context file path
    #[arg(
        short = 'c',
        long = "key-context",
        conflicts_with = "key_context_handle"
    )]
    pub key_context: Option<PathBuf>,

    /// RSA key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "key-context-handle", value_parser = parse_hex_u32, conflicts_with = "key_context")]
    pub key_context_handle: Option<u32>,

    /// Encryption scheme (rsaes, oaep, null)
    #[arg(short = 's', long = "scheme", default_value = "rsaes")]
    pub scheme: String,

    /// Hash algorithm for OAEP (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Label for OAEP (optional)
    #[arg(short = 'l', long = "label")]
    pub label: Option<String>,

    /// Input file (plaintext)
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Output file (ciphertext)
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl RsaEncryptCmd {
    fn key_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.key_context, self.key_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --key-context or --key-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;
        let key_handle = load_key_from_source(&mut ctx, &self.key_context_source()?)?;

        let hash_alg = crate::parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let scheme = parse_rsa_scheme(&self.scheme, hash_alg)?;

        let plaintext = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let message = PublicKeyRsa::try_from(plaintext)
            .map_err(|e| anyhow::anyhow!("invalid plaintext: {e}"))?;

        let label_data = match &self.label {
            Some(l) => {
                let bytes = l.as_bytes().to_vec();
                Data::try_from(bytes).map_err(|e| anyhow::anyhow!("label too large: {e}"))?
            }
            None => Data::default(),
        };

        let ciphertext = ctx
            .execute_without_session(|ctx| ctx.rsa_encrypt(key_handle, message, scheme, label_data))
            .context("TPM2_RSA_Encrypt failed")?;

        output::write_to_file(&self.output, ciphertext.value())?;
        info!("ciphertext saved to {}", self.output.display());
        Ok(())
    }
}

fn parse_rsa_scheme(
    s: &str,
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
) -> anyhow::Result<RsaDecryptionScheme> {
    match s.to_lowercase().as_str() {
        "rsaes" => Ok(RsaDecryptionScheme::RsaEs),
        "oaep" => Ok(RsaDecryptionScheme::Oaep(
            tss_esapi::structures::HashScheme::new(hash_alg),
        )),
        "null" => Ok(RsaDecryptionScheme::Null),
        _ => anyhow::bail!("unsupported RSA scheme: {s}"),
    }
}
