use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::Name;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

/// Gate a policy on a specific duplication target parent.
///
/// Wraps TPM2_PolicyDuplicationSelect.
#[derive(Parser)]
pub struct PolicyDuplicationSelectCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Object name file (name of object to be duplicated)
    #[arg(short = 'n', long = "object-name")]
    pub object_name: PathBuf,

    /// New parent name file
    #[arg(short = 'N', long = "parent-name")]
    pub parent_name: PathBuf,

    /// Include the object name in the policy hash
    #[arg(long = "include-object", default_value = "false")]
    pub include_object: bool,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyDuplicationSelectCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let obj_data = std::fs::read(&self.object_name)
            .with_context(|| format!("reading object name from {}", self.object_name.display()))?;
        let object_name =
            Name::try_from(obj_data).map_err(|e| anyhow::anyhow!("invalid object name: {e}"))?;

        let parent_data = std::fs::read(&self.parent_name)
            .with_context(|| format!("reading parent name from {}", self.parent_name.display()))?;
        let new_parent_name =
            Name::try_from(parent_data).map_err(|e| anyhow::anyhow!("invalid parent name: {e}"))?;

        ctx.policy_duplication_select(
            policy_session,
            object_name,
            new_parent_name,
            self.include_object,
        )
        .context("TPM2_PolicyDuplicationSelect failed")?;

        info!("policy duplication select set");

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
