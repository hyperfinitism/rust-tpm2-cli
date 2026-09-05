// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::EccKeyExchangeAlgorithm;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::cmd::ecc::{bytes_to_ecc_point, ecc_point_to_bytes};
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct Zgen2PhaseCmd {
    /// Key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Authorization value for the key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Other party's static public point file (raw x||y bytes)
    #[arg(long = "static-public")]
    pub static_public: PathBuf,

    /// Other party's ephemeral public point file (raw x||y bytes)
    #[arg(long = "ephemeral-public")]
    pub ephemeral_public: PathBuf,

    /// Key exchange scheme (ecdh, sm2)
    #[arg(short = 's', long = "scheme", default_value = "ecdh", value_parser = parse::parse_ecc_key_exchange_algorithm)]
    pub scheme: EccKeyExchangeAlgorithm,

    /// Counter from the commit
    #[arg(short = 't', long = "counter")]
    pub counter: u16,

    /// Output file for Z1 point
    #[arg(long = "output-Z1")]
    pub output_z1: PathBuf,

    /// Output file for Z2 point
    #[arg(long = "output-Z2")]
    pub output_z2: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl Zgen2PhaseCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let key_handle = load_key_from_source(&mut ctx, &self.key_context)?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(key_handle.into(), auth.clone())
                .context("failed to set key authorization")?;
        }

        let static_data = std::fs::read(&self.static_public)?;
        let ephemeral_data = std::fs::read(&self.ephemeral_public)?;

        let in_qs = bytes_to_ecc_point(&static_data)?;
        let in_qe = bytes_to_ecc_point(&ephemeral_data)?;

        let (z1, z2) = execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.zgen_2phase(key_handle, in_qs, in_qe, self.scheme, self.counter)
        })
        .context("TPM2_ZGen_2Phase failed")?;

        std::fs::write(&self.output_z1, ecc_point_to_bytes(&z1))
            .with_context(|| format!("writing Z1 to {}", self.output_z1.display()))?;
        info!("Z1 saved to {}", self.output_z1.display());

        std::fs::write(&self.output_z2, ecc_point_to_bytes(&z2))
            .with_context(|| format!("writing Z2 to {}", self.output_z2.display()))?;
        info!("Z2 saved to {}", self.output_z2.display());

        info!("ZGen_2Phase succeeded");
        Ok(())
    }
}
