// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{Data, SymmetricDefinitionObject};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;

/// Duplicate a loaded object for use in a different hierarchy.
///
/// Wraps TPM2_Duplicate.
#[derive(Parser)]
pub struct DuplicateCmd {
    /// Object to duplicate (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "object-context", value_parser = parse_context_source)]
    pub object_context: ContextSource,

    /// New parent key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "parent-context", value_parser = parse_context_source, conflicts_with = "parent_context_null")]
    pub parent_context: Option<ContextSource>,

    /// Use a null parent handle
    #[arg(long = "parent-context-null", conflicts_with = "parent_context")]
    pub parent_context_null: bool,

    /// Auth value for the object
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Symmetric algorithm for inner wrapper (aes128cfb, null)
    #[arg(short = 'G', long = "wrapper-algorithm", default_value = "null")]
    pub wrapper_algorithm: String,

    /// Input encryption key file (optional)
    #[arg(short = 'i', long = "encryptionkey-in")]
    pub encryption_key_in: Option<PathBuf>,

    /// Output file for the encrypted duplicate
    #[arg(short = 'r', long = "private")]
    pub private_out: PathBuf,

    /// Output file for the encryption key (if generated)
    #[arg(short = 'k', long = "encryptionkey-out")]
    pub encryption_key_out: Option<PathBuf>,

    /// Output file for the encrypted seed
    #[arg(short = 's', long = "encrypted-seed")]
    pub encrypted_seed: PathBuf,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl DuplicateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let object_handle = load_object_from_source(&mut ctx, &self.object_context)?;
        let parent_handle = if self.parent_context_null {
            tss_esapi::handles::ObjectHandle::Null
        } else {
            match &self.parent_context {
                Some(src) => load_object_from_source(&mut ctx, src)?,
                None => anyhow::bail!("--parent-context or --parent-context-null is required"),
            }
        };

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(object_handle, auth)
                .context("tr_set_auth failed")?;
        }

        let encryption_key = match &self.encryption_key_in {
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
        let (enc_key, duplicate_private, encrypted_secret) =
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.duplicate(
                    object_handle,
                    parent_handle,
                    encryption_key.clone(),
                    sym_alg,
                )
            })
            .context("TPM2_Duplicate failed")?;

        std::fs::write(&self.private_out, duplicate_private.value())
            .with_context(|| format!("writing private to {}", self.private_out.display()))?;
        info!("duplicate private saved to {}", self.private_out.display());

        std::fs::write(&self.encrypted_seed, encrypted_secret.value())
            .with_context(|| format!("writing seed to {}", self.encrypted_seed.display()))?;
        info!("encrypted seed saved to {}", self.encrypted_seed.display());

        if let Some(ref path) = self.encryption_key_out {
            std::fs::write(path, enc_key.value())
                .with_context(|| format!("writing encryption key to {}", path.display()))?;
            info!("encryption key saved to {}", path.display());
        }

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
