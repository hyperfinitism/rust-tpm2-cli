// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::reserved_handles::HierarchyAuth;
use tss_esapi::structures::{Auth, Digest};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct SetPrimaryPolicyCmd {
    /// Hierarchy (o/owner, e/endorsement, p/platform, l/lockout)
    #[arg(short = 'C', long = "hierarchy", value_parser = parse::parse_hierarchy_auth)]
    pub hierarchy: HierarchyAuth,

    /// Authorization value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Policy digest file
    #[arg(short = 'L', long = "policy")]
    pub policy: PathBuf,

    /// Hash algorithm used for the policy
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl SetPrimaryPolicyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(self.hierarchy.into(), auth.clone())
                .context("failed to set hierarchy authorization")?;
        }

        let policy_data = std::fs::read(&self.policy)
            .with_context(|| format!("reading policy from {}", self.policy.display()))?;

        let auth_policy = Digest::try_from(policy_data)
            .map_err(|e| anyhow::anyhow!("invalid policy digest: {e}"))?;

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.set_primary_policy(self.hierarchy, auth_policy, self.hash_algorithm)
        })
        .context("TPM2_SetPrimaryPolicy failed")?;

        info!("primary policy set for hierarchy {:?}", self.hierarchy);
        Ok(())
    }
}
