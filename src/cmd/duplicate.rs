// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use log::info;
use tss_esapi::structures::{Auth, Data, SymmetricDefinitionObject};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
#[command(group(
    ArgGroup::new("parent")
        .required(true)
        .multiple(false)
        .args(["parent_context", "parent_context_null"])
))]
pub struct DuplicateCmd {
    /// Object to duplicate (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "object-context", value_parser = parse_context_source)]
    pub object_context: ContextSource,

    /// New parent key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "parent-context", value_parser = parse_context_source)]
    pub parent_context: Option<ContextSource>,

    /// Use a null parent handle
    #[arg(long = "parent-context-null")]
    pub parent_context_null: bool,

    /// Authorization value for the object
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Symmetric algorithm for inner wrapper (aes128cfb, null)
    #[arg(short = 'G', long = "wrapper-algorithm", default_value = "null", value_parser = parse::parse_wrapper_algorithm)]
    pub wrapper_algorithm: SymmetricDefinitionObject,

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

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl DuplicateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let object_handle = load_object_from_source(&mut ctx, &self.object_context)?;
        let parent_handle = if self.parent_context_null {
            tss_esapi::handles::ObjectHandle::Null
        } else {
            load_object_from_source(
                &mut ctx,
                self.parent_context
                    .as_ref()
                    .expect("clap requires exactly one parent"),
            )?
        };

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(object_handle, auth.clone())
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

        let session_path = self.session.as_deref();
        let (enc_key, duplicate_private, encrypted_secret) =
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.duplicate(
                    object_handle,
                    parent_handle,
                    encryption_key.clone(),
                    self.wrapper_algorithm,
                )
            })
            .context("TPM2_Duplicate failed")?;

        std::fs::write(&self.private_out, duplicate_private.as_bytes())
            .with_context(|| format!("writing private to {}", self.private_out.display()))?;
        info!("duplicate private saved to {}", self.private_out.display());

        std::fs::write(&self.encrypted_seed, encrypted_secret.as_bytes())
            .with_context(|| format!("writing seed to {}", self.encrypted_seed.display()))?;
        info!("encrypted seed saved to {}", self.encrypted_seed.display());

        if let Some(ref path) = self.encryption_key_out {
            std::fs::write(path, enc_key.as_bytes())
                .with_context(|| format!("writing encryption key to {}", path.display()))?;
            info!("encryption key saved to {}", path.display());
        }

        Ok(())
    }
}
