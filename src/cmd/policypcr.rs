// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::Digest;

use tss_esapi::structures::PcrSelectionList;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::load_session_from_file;
#[derive(Parser)]
pub struct PolicyPcrCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// PCR selection (e.g. sha256:0,1,2)
    #[arg(short = 'l', long = "pcr-list", value_parser = parse::parse_pcr_selection)]
    pub pcr_list: PcrSelectionList,

    /// Expected PCR digest (hex). If empty, uses current PCR values.
    #[arg(short = 'f', long = "pcr-digest", value_parser = parse::parse_hex_digest)]
    pub pcr_digest: Option<Digest>,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyPcrCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let pcr_selection = self.pcr_list.clone();

        let pcr_digest = self.pcr_digest.clone().unwrap_or_default();

        ctx.policy_pcr(policy_session, pcr_digest, pcr_selection)
            .context("TPM2_PolicyPCR failed")?;

        info!("policy PCR set");

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
