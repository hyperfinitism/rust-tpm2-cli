// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::cmd::ecc::{bytes_to_ecc_point, ecc_point_to_bytes};
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct EcdhZgenCmd {
    /// ECC key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Authorization value for the key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Input file containing the public point (raw x||y bytes)
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Output file for the shared secret Z point (raw x||y bytes)
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl EcdhZgenCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.key_context)?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(key_handle.into(), auth.clone())
                .context("tr_set_auth failed")?;
        }

        let point_data = std::fs::read(&self.public)
            .with_context(|| format!("reading public point from {}", self.public.display()))?;
        let in_point = bytes_to_ecc_point(&point_data)?;

        let session_path = self.session.as_deref();
        let z_point = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.ecdh_z_gen(key_handle, in_point.clone())
        })
        .context("TPM2_ECDH_ZGen failed")?;

        std::fs::write(&self.output, ecc_point_to_bytes(&z_point))
            .with_context(|| format!("writing Z point to {}", self.output.display()))?;
        info!("shared secret Z saved to {}", self.output.display());

        Ok(())
    }
}
