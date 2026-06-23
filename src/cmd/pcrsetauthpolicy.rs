// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::{AuthHandle, PcrHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Digest};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct PcrSetAuthPolicyCmd {
    /// PCR index
    #[arg(value_parser = parse::parse_pcr_handle)]
    pub pcr: PcrHandle,

    /// Policy digest file
    #[arg(short = 'L', long = "policy")]
    pub policy: PathBuf,

    /// Hash algorithm used for the policy digest
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Authorization value for the platform hierarchy
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl PcrSetAuthPolicyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(AuthHandle::Platform.into(), auth.clone())
                .context("failed to set platform authorization")?;
        }

        let policy = std::fs::read(&self.policy)
            .with_context(|| format!("reading policy digest from {}", self.policy.display()))?;
        let policy =
            Digest::try_from(policy).map_err(|e| anyhow::anyhow!("invalid policy digest: {e}"))?;

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.pcr_set_auth_policy(
                AuthHandle::Platform,
                policy.clone(),
                self.hash_algorithm,
                self.pcr,
            )
        })
        .context("TPM2_PCR_SetAuthPolicy failed")?;

        info!("PCR authorization policy set");
        Ok(())
    }
}
