// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use log::info;
use tss_esapi::structures::{Auth, EncryptedSecret, Name, Private};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
#[command(group(
    ArgGroup::new("new_parent")
        .required(true)
        .multiple(false)
        .args(["new_parent_context", "new_parent_null"])
))]
pub struct RewrapCmd {
    /// Current parent context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "old-parent-context", value_parser = parse_context_source)]
    pub old_parent_context: ContextSource,

    /// New parent context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "new-parent-context", value_parser = parse_context_source)]
    pub new_parent_context: Option<ContextSource>,

    /// Use the null hierarchy as the new parent
    #[arg(long = "new-parent-null")]
    pub new_parent_null: bool,

    /// Authorization value for the current parent
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Input duplicated private area
    #[arg(short = 'i', long = "private")]
    pub private: PathBuf,

    /// Input object name
    #[arg(short = 'n', long = "name")]
    pub name: PathBuf,

    /// Input encrypted seed
    #[arg(short = 's', long = "encrypted-seed")]
    pub encrypted_seed: PathBuf,

    /// Output rewrapped private area
    #[arg(short = 'o', long = "out-private")]
    pub out_private: PathBuf,

    /// Output rewrapped encrypted seed
    #[arg(long = "out-encrypted-seed")]
    pub out_encrypted_seed: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl RewrapCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let old_parent = load_object_from_source(&mut ctx, &self.old_parent_context)?;
        let new_parent = if self.new_parent_null {
            tss_esapi::handles::ObjectHandle::Null
        } else {
            let source = self
                .new_parent_context
                .as_ref()
                .expect("clap requires exactly one new parent");
            load_object_from_source(&mut ctx, source)?
        };

        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(old_parent, auth.clone())
                .context("failed to set current parent authorization")?;
        }

        let duplicate = Private::try_from(std::fs::read(&self.private)?)
            .map_err(|e| anyhow::anyhow!("invalid duplicated private area: {e}"))?;
        let name = Name::try_from(std::fs::read(&self.name)?)
            .map_err(|e| anyhow::anyhow!("invalid object name: {e}"))?;
        let seed = EncryptedSecret::try_from(std::fs::read(&self.encrypted_seed)?)
            .map_err(|e| anyhow::anyhow!("invalid encrypted seed: {e}"))?;

        let (out_private, out_seed) =
            execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
                ctx.rewrap(
                    old_parent,
                    new_parent,
                    duplicate.clone(),
                    name.clone(),
                    seed.clone(),
                )
            })
            .context("TPM2_Rewrap failed")?;

        std::fs::write(&self.out_private, out_private.as_bytes())
            .with_context(|| format!("writing private area to {}", self.out_private.display()))?;
        std::fs::write(&self.out_encrypted_seed, out_seed.as_bytes()).with_context(|| {
            format!(
                "writing encrypted seed to {}",
                self.out_encrypted_seed.display()
            )
        })?;
        info!("rewrapped duplicate written");
        Ok(())
    }
}
