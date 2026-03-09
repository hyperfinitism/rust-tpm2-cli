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

/// Bind a policy to specific object names.
///
/// Wraps TPM2_PolicyNameHash.
#[derive(Parser)]
pub struct PolicyNameHashCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Name hash file (binary digest)
    #[arg(long = "namehash")]
    pub namehash: PathBuf,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyNameHashCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let data = std::fs::read(&self.namehash)
            .with_context(|| format!("reading name hash from {}", self.namehash.display()))?;
        let name_hash =
            Digest::try_from(data).map_err(|e| anyhow::anyhow!("invalid name hash: {e}"))?;

        ctx.policy_name_hash(policy_session, name_hash)
            .context("TPM2_PolicyNameHash failed")?;

        info!("policy name hash set");

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
