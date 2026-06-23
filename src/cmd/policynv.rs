// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::SessionHandle;
use tss_esapi::interface_types::ArithmeticComparison;
use tss_esapi::structures::{Auth, Digest};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{load_nv_index, nv_auth_from_entity, set_nv_auth};
use crate::parse::{self, NvAuthEntity};
use crate::session::{load_optional_auth_session, load_session_from_file, save_session_and_forget};
#[derive(Parser)]
pub struct PolicyNvCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// NV index (hex, e.g. 0x01000001)
    #[arg(short = 'i', long = "nv-index", value_parser = parse::parse_nv_index)]
    pub nv_index: tss_esapi::handles::NvIndexTpmHandle,

    /// Authorization entity for the NV index (owner, platform, or nv-index)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Authorization value for the hierarchy
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Operand B (hex bytes for comparison)
    #[arg(long = "operand-b", value_parser = parse::parse_hex_digest)]
    pub operand_b: Digest,

    /// Offset within the NV data
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Operation (eq, neq, sgt, ugt, slt, ult, sge, uge, sle, ule, bs, bc)
    #[arg(long = "operation", default_value = "eq", value_parser = parse::parse_tpm2_operation)]
    pub operation: ArithmeticComparison,

    /// Session context file for NV authorization
    #[arg(long = "auth-session")]
    pub auth_session: Option<PathBuf>,
}

impl PolicyNvCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;

        let nv_handle = load_nv_index(&mut ctx, self.nv_index)?;

        let nv_auth = nv_auth_from_entity(self.hierarchy, nv_handle);

        if let Some(ref auth) = self.auth {
            set_nv_auth(&mut ctx, nv_auth, auth.clone())?;
        }

        let auth_session = load_optional_auth_session(&mut ctx, self.auth_session.as_deref())?;
        ctx.execute_with_session(Some(auth_session), |ctx| {
            ctx.policy_nv(
                policy_session,
                nv_auth,
                nv_handle,
                self.operand_b.clone(),
                self.offset,
                self.operation,
            )
        })
        .context("TPM2_PolicyNV failed")?;

        let session_handle = SessionHandle::from(policy_session);
        save_session_and_forget(ctx, session_handle, &self.session)?;
        info!("policy NV asserted");
        Ok(())
    }
}
