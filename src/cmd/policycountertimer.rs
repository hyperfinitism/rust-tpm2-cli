// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::SessionHandle;
use tss_esapi::interface_types::ArithmeticComparison;
use tss_esapi::structures::Digest;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::{load_session_from_file, save_session_and_forget};
#[derive(Parser)]
pub struct PolicyCounterTimerCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Operand B (hex bytes for comparison)
    #[arg(long = "operand-b", value_parser = parse::parse_hex_digest)]
    pub operand_b: Digest,

    /// Offset in the TPMS_TIME_INFO structure
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Operation (eq, neq, sgt, ugt, slt, ult, sge, uge, sle, ule, bs, bc)
    #[arg(long = "operation", default_value = "eq", value_parser = parse::parse_tpm2_operation)]
    pub operation: ArithmeticComparison,
}

impl PolicyCounterTimerCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        ctx.policy_counter_timer(
            policy_session,
            self.operand_b.clone(),
            self.offset,
            self.operation,
        )
        .context("TPM2_PolicyCounterTimer failed")?;

        let session_handle = SessionHandle::from(policy_session);
        save_session_and_forget(ctx, session_handle, &self.session)?;
        info!("policy counter/timer asserted");
        Ok(())
    }
}
