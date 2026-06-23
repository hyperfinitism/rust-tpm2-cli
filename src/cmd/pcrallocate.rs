// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::AuthHandle;
use tss_esapi::structures::Auth;
use tss_esapi::structures::PcrSelectionList;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct PcrAllocateCmd {
    /// Authorization value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// PCR allocation (e.g. sha256:0,1,2+sha1:all)
    #[arg(value_parser = parse::parse_pcr_allocation)]
    pub allocation: PcrSelectionList,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl PcrAllocateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(AuthHandle::Platform.into(), auth.clone())
                .context("failed to set PCR allocation authorization")?;
        }

        let result = execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.pcr_allocate(AuthHandle::Platform, self.allocation.clone())
        })
        .context("TPM2_PCR_Allocate failed")?;

        if bool::from(result.allocation_success) {
            info!(
                "PCR allocation succeeded (max_pcr={}, needed={}, available={})",
                result.max_pcr, result.size_needed, result.size_available
            );
        } else {
            info!(
                "PCR allocation will take effect after TPM reset (needed={}, available={})",
                result.size_needed, result.size_available
            );
        }

        Ok(())
    }
}
