use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{Data, PublicKeyRsa, RsaDecryptionScheme};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::output;
use crate::parse;
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Perform RSA decryption using a TPM-loaded key.
///
/// Wraps TPM2_RSA_Decrypt.
#[derive(Parser)]
pub struct RsaDecryptCmd {
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

    /// Auth value for the key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Decryption scheme (rsaes, oaep, null)
    #[arg(short = 's', long = "scheme", default_value = "rsaes")]
    pub scheme: String,

    /// Hash algorithm for OAEP (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

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

        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let scheme = parse_rsa_scheme(&self.scheme, hash_alg)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(key_handle.into(), auth)
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

        output::write_to_file(&self.output, plaintext.value())?;
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
