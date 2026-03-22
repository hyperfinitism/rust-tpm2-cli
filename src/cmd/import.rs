// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{Data, EncryptedSecret, Private, Public, SymmetricDefinitionObject};
use tss_esapi::traits::UnMarshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;

/// Import an external object into the TPM under a parent key.
///
/// Wraps TPM2_Import.
#[derive(Parser)]
pub struct ImportCmd {
    /// Parent key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "parent-context", value_parser = parse_context_source)]
    pub parent_context: ContextSource,

    /// Auth value for the parent key
    #[arg(short = 'P', long = "parent-auth")]
    pub parent_auth: Option<String>,

    /// Input public file (marshaled TPM2B_PUBLIC)
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Input duplicate private file (marshaled TPM2B_PRIVATE)
    #[arg(short = 'r', long = "private")]
    pub private: PathBuf,

    /// Input encrypted seed file (marshaled TPM2B_ENCRYPTED_SECRET)
    #[arg(short = 's', long = "encrypted-seed")]
    pub encrypted_seed: PathBuf,

    /// Input encryption key file (optional)
    #[arg(short = 'k', long = "encryption-key")]
    pub encryption_key: Option<PathBuf>,

    /// Symmetric algorithm for inner wrapper (aes128cfb, null)
    #[arg(short = 'G', long = "wrapper-algorithm", default_value = "null")]
    pub wrapper_algorithm: String,

    /// Output file for the imported private
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl ImportCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let parent_handle = load_object_from_source(&mut ctx, &self.parent_context)?;

        if let Some(ref auth_str) = self.parent_auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(parent_handle, auth)
                .context("tr_set_auth failed")?;
        }

        let pub_data = std::fs::read(&self.public)
            .with_context(|| format!("reading public from {}", self.public.display()))?;
        let public = Public::unmarshall(&pub_data)
            .map_err(|e| anyhow::anyhow!("failed to unmarshal public: {e}"))?;

        let priv_data = std::fs::read(&self.private)
            .with_context(|| format!("reading private from {}", self.private.display()))?;
        let duplicate = Private::try_from(priv_data)
            .map_err(|e| anyhow::anyhow!("failed to unmarshal private: {e}"))?;

        let seed_data = std::fs::read(&self.encrypted_seed)
            .with_context(|| format!("reading seed from {}", self.encrypted_seed.display()))?;
        let encrypted_secret = EncryptedSecret::try_from(seed_data)
            .map_err(|e| anyhow::anyhow!("failed to unmarshal encrypted seed: {e}"))?;

        let enc_key = match &self.encryption_key {
            Some(path) => {
                let data = std::fs::read(path)
                    .with_context(|| format!("reading encryption key from {}", path.display()))?;
                Some(
                    Data::try_from(data)
                        .map_err(|e| anyhow::anyhow!("encryption key too large: {e}"))?,
                )
            }
            None => None,
        };

        let sym_alg = parse_wrapper_algorithm(&self.wrapper_algorithm)?;

        let session_path = self.session.as_deref();
        let imported_private = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.import(
                parent_handle,
                enc_key.clone(),
                public.clone(),
                duplicate.clone(),
                encrypted_secret.clone(),
                sym_alg,
            )
        })
        .context("TPM2_Import failed")?;

        let out_bytes = imported_private.value();
        std::fs::write(&self.output, out_bytes)
            .with_context(|| format!("writing output to {}", self.output.display()))?;
        info!("imported private saved to {}", self.output.display());

        Ok(())
    }
}

fn parse_wrapper_algorithm(s: &str) -> anyhow::Result<SymmetricDefinitionObject> {
    match s.to_lowercase().as_str() {
        "null" => Ok(SymmetricDefinitionObject::Null),
        "aes128cfb" | "aes" => Ok(SymmetricDefinitionObject::Aes {
            key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        }),
        "aes256cfb" => Ok(SymmetricDefinitionObject::Aes {
            key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes256,
            mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
        }),
        _ => anyhow::bail!("unsupported wrapper algorithm: {s}"),
    }
}
