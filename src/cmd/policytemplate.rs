// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::Digest;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

/// Bind a policy to a specific object creation template.
///
/// Wraps TPM2_PolicyTemplate.
#[derive(Parser)]
pub struct PolicyTemplateCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Template hash file (binary digest)
    #[arg(long = "template-hash")]
    pub template_hash: PathBuf,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyTemplateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let data = std::fs::read(&self.template_hash).with_context(|| {
            format!(
                "reading template hash from {}",
                self.template_hash.display()
            )
        })?;
        let template_hash =
            Digest::try_from(data).map_err(|e| anyhow::anyhow!("invalid template hash: {e}"))?;

        ctx.policy_template(policy_session, template_hash)
            .context("TPM2_PolicyTemplate failed")?;

        info!("policy template set");

        if let Some(ref path) = self.policy {
            let digest = ctx
                .policy_get_digest(policy_session)
                .context("TPM2_PolicyGetDigest failed")?;
            std::fs::write(path, digest.value())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        Ok(())
    }
}
