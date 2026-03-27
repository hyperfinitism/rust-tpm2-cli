// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Data, PublicKeyRsa, RsaDecryptionScheme};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;

/// Perform RSA decryption using a TPM-loaded key.
///
/// Wraps TPM2_RSA_Decrypt.
#[derive(Parser)]
pub struct RsaDecryptCmd {
    /// RSA key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Auth value for the key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Decryption scheme (rsaes, oaep, null)
    #[arg(short = 's', long = "scheme", default_value = "rsaes")]
    pub scheme: String,

    /// Hash algorithm for OAEP (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Label for OAEP (optional)
    #[arg(short = 'l', long = "label")]
    pub label: Option<String>,

    /// Input file (ciphertext)
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Output file (plaintext)
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl RsaDecryptCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;
        let key_handle = load_key_from_source(&mut ctx, &self.key_context)?;

        let scheme = parse_rsa_scheme(&self.scheme, self.hash_algorithm)?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(key_handle.into(), auth.clone())
                .context("tr_set_auth failed")?;
        }

        let ciphertext_data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;
        let cipher_text = PublicKeyRsa::try_from(ciphertext_data)
            .map_err(|e| anyhow::anyhow!("invalid ciphertext: {e}"))?;

        let label_data = match &self.label {
            Some(l) => {
                let bytes = l.as_bytes().to_vec();
                Data::try_from(bytes).map_err(|e| anyhow::anyhow!("label too large: {e}"))?
            }
            None => Data::default(),
        };

        let session_path = self.session.as_deref();
        let plaintext = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.rsa_decrypt(key_handle, cipher_text.clone(), scheme, label_data.clone())
        })
        .context("TPM2_RSA_Decrypt failed")?;

        output::write_to_file(&self.output, plaintext.as_bytes())?;
        info!("plaintext saved to {}", self.output.display());
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
