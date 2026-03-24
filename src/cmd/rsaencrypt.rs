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
use crate::parse::parse_context_source;

/// Perform RSA encryption using a TPM-loaded key.
///
/// Wraps TPM2_RSA_Encrypt.
#[derive(Parser)]
pub struct RsaEncryptCmd {
    /// RSA key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

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
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;
        let key_handle = load_key_from_source(&mut ctx, &self.key_context)?;

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

        output::write_to_file(&self.output, ciphertext.as_bytes())?;
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
