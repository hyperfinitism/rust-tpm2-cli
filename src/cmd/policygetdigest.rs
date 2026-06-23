// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;
use crate::session::{load_session_from_file, save_session_and_forget};
#[derive(Parser)]
pub struct PolicyGetDigestCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Output file for the policy digest
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
}

impl PolicyGetDigestCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let digest = ctx
            .policy_get_digest(policy_session)
            .context("TPM2_PolicyGetDigest failed")?;

        if let Some(path) = &self.output {
            output::write_to_file(path, digest.as_bytes())?;
        } else {
            output::print_hex(digest.as_bytes());
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        save_session_and_forget(ctx, handle, &self.session)
    }
}
