// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

/// Restart a policy session, clearing its policy digest.
///
/// Wraps TPM2_PolicyRestart.
#[derive(Parser)]
pub struct PolicyRestartCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,
}

impl PolicyRestartCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        ctx.policy_restart(policy_session)
            .context("TPM2_PolicyRestart failed")?;

        info!("policy session restarted");

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        Ok(())
    }
}
