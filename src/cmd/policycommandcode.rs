use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::CommandCode;
use tss_esapi::constants::SessionType;
use tss_esapi::constants::tss::*;
use tss_esapi::handles::{ObjectHandle, SessionHandle};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

/// Restrict policy to a specific TPM command.
///
/// Wraps TPM2_PolicyCommandCode.
#[derive(Parser)]
pub struct PolicyCommandCodeCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Command code (hex value, e.g. 0x153 for TPM2_CC_Unseal)
    #[arg()]
    pub command_code: String,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicyCommandCodeCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let code = parse_command_code(&self.command_code)?;

        ctx.policy_command_code(policy_session, code)
            .context("TPM2_PolicyCommandCode failed")?;

        info!("policy command code set");

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

fn parse_command_code(s: &str) -> anyhow::Result<CommandCode> {
    // Try hex value first.
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if let Ok(raw) = u32::from_str_radix(stripped, 16) {
        return CommandCode::try_from(raw)
            .map_err(|e| anyhow::anyhow!("invalid command code 0x{raw:08x}: {e}"));
    }

    // Try known names.
    match s.to_lowercase().as_str() {
        "unseal" => CommandCode::try_from(TPM2_CC_Unseal),
        "sign" => CommandCode::try_from(TPM2_CC_Sign),
        "nv_read" | "nvread" => CommandCode::try_from(TPM2_CC_NV_Read),
        "nv_write" | "nvwrite" => CommandCode::try_from(TPM2_CC_NV_Write),
        "duplicate" => CommandCode::try_from(TPM2_CC_Duplicate),
        "certify" => CommandCode::try_from(TPM2_CC_Certify),
        "quote" => CommandCode::try_from(TPM2_CC_Quote),
        "create" => CommandCode::try_from(TPM2_CC_Create),
        _ => anyhow::bail!("unknown command code: {s}"),
    }
    .map_err(|e| anyhow::anyhow!("invalid command code: {e}"))
}
