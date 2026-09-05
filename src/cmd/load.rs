// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{Auth, Private, PublicBuffer};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct LoadCmd {
    /// Parent key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "parent-context", value_parser = parse_context_source)]
    pub parent_context: ContextSource,

    /// Authorization value for the parent key
    #[arg(short = 'P', long = "parent-auth", value_parser = parse::parse_auth)]
    pub parent_auth: Option<Auth>,

    /// Private key file (raw binary)
    #[arg(short = 'r', long = "private")]
    pub private: PathBuf,

    /// Public key file (raw binary)
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Output context file for the loaded key
    #[arg(short = 'c', long = "context")]
    pub context: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl LoadCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let parent_handle = load_key_from_source(&mut ctx, &self.parent_context)?;
        if let Some(auth) = &self.parent_auth {
            ctx.tr_set_auth(parent_handle.into(), auth.clone())
                .context("failed to set parent key authorization")?;
        }

        let priv_bytes = std::fs::read(&self.private)
            .with_context(|| format!("reading private file: {}", self.private.display()))?;
        let pub_bytes = std::fs::read(&self.public)
            .with_context(|| format!("reading public file: {}", self.public.display()))?;

        let private =
            Private::try_from(priv_bytes).map_err(|e| anyhow::anyhow!("invalid private: {e}"))?;
        let pub_buffer = PublicBuffer::try_from(pub_bytes)
            .map_err(|e| anyhow::anyhow!("invalid public buffer: {e}"))?;
        let public = tss_esapi::structures::Public::try_from(pub_buffer)
            .map_err(|e| anyhow::anyhow!("invalid public: {e}"))?;

        let session_path = self.session.as_deref();
        let key_handle = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.load(parent_handle, private.clone(), public.clone())
        })
        .context("TPM2_Load failed")?;

        println!("handle: 0x{:08x}", u32::from(key_handle));

        if let Some(ref path) = self.context {
            let saved = ctx
                .context_save(key_handle.into())
                .context("context_save failed")?;
            let json = serde_json::to_string(&saved)?;
            std::fs::write(path, json)
                .with_context(|| format!("writing context to {}", path.display()))?;
            info!("context saved to {}", path.display());
        }

        Ok(())
    }
}
