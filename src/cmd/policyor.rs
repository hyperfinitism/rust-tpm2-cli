// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::{Digest, DigestList};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

/// Compound multiple policies with logical OR.
///
/// Wraps TPM2_PolicyOR.
#[derive(Parser)]
pub struct PolicyOrCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Policy digest files to OR together (at least 2)
    #[arg(short = 'l', long = "policy-list", num_args = 2..)]
    pub policy_list: Vec<PathBuf>,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyOrCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        if self.policy_list.len() < 2 {
            bail!("at least 2 policy digests required for OR");
        }

        let mut digest_list = DigestList::new();
        for path in &self.policy_list {
            let data = std::fs::read(path)
                .with_context(|| format!("reading policy digest from {}", path.display()))?;
            let digest = Digest::try_from(data)
                .map_err(|e| anyhow::anyhow!("invalid digest from {}: {e}", path.display()))?;
            digest_list
                .add(digest)
                .map_err(|e| anyhow::anyhow!("failed to add digest: {e}"))?;
        }

        ctx.policy_or(policy_session, digest_list)
            .context("TPM2_PolicyOR failed")?;

        info!("policy OR set");

        if let Some(ref path) = self.policy {
            let digest = ctx
                .policy_get_digest(policy_session)
                .context("TPM2_PolicyGetDigest failed")?;
            std::fs::write(path, digest.as_bytes())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
            info!("policy digest saved to {}", path.display());
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        Ok(())
    }
}
