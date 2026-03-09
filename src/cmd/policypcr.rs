use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::structures::Digest;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::load_session_from_file;

/// Gate a policy on the current PCR values.
///
/// Wraps TPM2_PolicyPCR.
#[derive(Parser)]
pub struct PolicyPcrCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// PCR selection (e.g. sha256:0,1,2)
    #[arg(short = 'l', long = "pcr-list")]
    pub pcr_list: String,

    /// Expected PCR digest (hex). If empty, uses current PCR values.
    #[arg(short = 'f', long = "pcr-digest")]
    pub pcr_digest: Option<String>,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyPcrCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let pcr_selection = parse::parse_pcr_selection(&self.pcr_list)?;

        let pcr_digest = match &self.pcr_digest {
            Some(hex_str) => {
                let bytes = hex::decode(hex_str)
                    .map_err(|e| anyhow::anyhow!("invalid PCR digest hex: {e}"))?;
                Digest::try_from(bytes).map_err(|e| anyhow::anyhow!("invalid PCR digest: {e}"))?
            }
            None => Digest::default(),
        };

        ctx.policy_pcr(policy_session, pcr_digest, pcr_selection)
            .context("TPM2_PolicyPCR failed")?;

        info!("policy PCR set");

        if let Some(ref path) = self.policy {
            let digest = ctx
                .policy_get_digest(policy_session)
                .context("TPM2_PolicyGetDigest failed")?;
            std::fs::write(path, digest.value())
                .with_context(|| format!("writing policy digest to {}", path.display()))?;
            info!("policy digest saved to {}", path.display());
        }

        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        crate::session::save_session_and_forget(ctx, handle, &self.session)?;

        Ok(())
    }
}
