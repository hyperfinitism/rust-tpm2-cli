// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Data, PublicKeyRsa};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::{self, parse_context_source};
#[derive(Parser)]
pub struct RsaEncryptCmd {
    /// RSA key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Encryption scheme (rsaes, oaep, null)
    #[arg(short = 's', long = "scheme", default_value = "rsaes", value_parser = parse::parse_rsa_decryption_scheme_kind)]
    pub scheme: parse::RsaDecryptionSchemeKind,

    /// Hash algorithm for OAEP
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Label for OAEP (optional)
    #[arg(short = 'l', long = "label", value_parser = parse::parse_utf8_data)]
    pub label: Option<Data>,

    /// Input file (plaintext)
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Output file (ciphertext)
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl RsaEncryptCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let key_handle = load_key_from_source(&mut ctx, &self.key_context)?;

        let scheme = self.scheme.with_hash(self.hash_algorithm);

        let plaintext = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let message = PublicKeyRsa::try_from(plaintext)
            .map_err(|e| anyhow::anyhow!("invalid plaintext: {e}"))?;

        let label_data = self.label.clone().unwrap_or_default();

        let ciphertext = ctx
            .execute_without_session(|ctx| ctx.rsa_encrypt(key_handle, message, scheme, label_data))
            .context("TPM2_RSA_Encrypt failed")?;

        output::write_to_file(&self.output, ciphertext.as_bytes())?;
        info!("ciphertext saved to {}", self.output.display());
        Ok(())
    }
}
