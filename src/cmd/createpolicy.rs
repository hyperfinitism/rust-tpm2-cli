// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::SymmetricDefinition;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Create a policy from a policy script (trial session).
///
/// Starts a trial policy session, prints its digest, and saves it.
/// Complex multi-step policies should be built by chaining individual
/// policy commands (policypcr, policycommandcode, etc.) against a
/// trial session created with `startauthsession --policy-session`.
///
/// This command provides a simple shortcut for common single-step policies.
#[derive(Parser)]
pub struct CreatePolicyCmd {
    /// Hash algorithm for the policy (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: PathBuf,

    /// Policy type: pcr
    #[arg(long = "policy-pcr")]
    pub policy_pcr: bool,

    /// PCR selection for --policy-pcr (e.g. sha256:0,1,2)
    #[arg(short = 'l', long = "pcr-list")]
    pub pcr_list: Option<String>,
}

impl CreatePolicyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;
        let hash_alg = crate::parse::parse_hashing_algorithm(&self.hash_algorithm)?;

        // Start a trial session.
        let session = ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_128_CFB,
                hash_alg,
            )
            .context("failed to start trial session")?
            .ok_or_else(|| anyhow::anyhow!("no session returned"))?;

        let policy_session: tss_esapi::interface_types::session_handles::PolicySession = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected policy session"))?;

        if self.policy_pcr {
            let pcr_spec = self
                .pcr_list
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--pcr-list required with --policy-pcr"))?;
            let pcr_selection = crate::parse::parse_pcr_selection(pcr_spec)?;
            ctx.policy_pcr(policy_session, Default::default(), pcr_selection)
                .context("TPM2_PolicyPCR failed")?;
        }

        let digest = ctx
            .policy_get_digest(policy_session)
            .context("TPM2_PolicyGetDigest failed")?;

        std::fs::write(&self.policy, digest.value())
            .with_context(|| format!("writing policy to {}", self.policy.display()))?;
        info!(
            "policy digest saved to {} ({} bytes)",
            self.policy.display(),
            digest.value().len()
        );

        // Flush the trial session.
        let obj_handle: ObjectHandle = SessionHandle::from(policy_session).into();
        ctx.flush_context(obj_handle)
            .context("failed to flush trial session")?;

        Ok(())
    }
}
