// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::attributes::LocalityAttributes;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

/// Gate a policy on the TPM locality.
///
/// Wraps TPM2_PolicyLocality.
#[derive(Parser)]
pub struct PolicyLocalityCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Locality value (0-4, or bitmask as hex)
    #[arg()]
    pub locality: String,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyLocalityCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let locality = parse_locality(&self.locality)?;

        ctx.policy_locality(policy_session, locality)
            .context("TPM2_PolicyLocality failed")?;

        info!("policy locality set");

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

fn parse_locality(s: &str) -> anyhow::Result<LocalityAttributes> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let val: u8 = if let Ok(v) = u8::from_str_radix(stripped, 16) {
        v
    } else {
        s.parse()
            .map_err(|_| anyhow::anyhow!("invalid locality: {s}"))?
    };
    Ok(LocalityAttributes(val))
}
