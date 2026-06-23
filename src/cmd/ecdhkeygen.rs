// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::cmd::ecc::ecc_point_to_bytes;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::parse_context_source;
#[derive(Parser)]
pub struct EcdhKeygenCmd {
    /// ECC key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Output file for the ephemeral public point Q
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Output file for the shared secret Z point
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl EcdhKeygenCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context)?;

        let (z_point, pub_point) = ctx
            .execute_without_session(|ctx| ctx.ecdh_key_gen(key_handle))
            .context("TPM2_ECDH_KeyGen failed")?;
        let pub_bytes = ecc_point_to_bytes(&pub_point);
        std::fs::write(&self.public, &pub_bytes)
            .with_context(|| format!("writing public point to {}", self.public.display()))?;
        info!("public point Q saved to {}", self.public.display());

        let z_bytes = ecc_point_to_bytes(&z_point);
        std::fs::write(&self.output, &z_bytes)
            .with_context(|| format!("writing shared secret to {}", self.output.display()))?;
        info!("shared secret Z saved to {}", self.output.display());

        Ok(())
    }
}
