// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::PcrHandle;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct PcrResetCmd {
    /// PCR index
    #[arg(value_parser = parse::parse_pcr_handle)]
    pub pcr: PcrHandle,

    /// Authorization value for the PCR
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl PcrResetCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(self.pcr.into(), auth.clone())
                .context("failed to set PCR authorization")?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.pcr_reset(self.pcr)
        })
        .context("TPM2_PCR_Reset failed")?;

        info!("PCR {:?} reset", self.pcr);
        Ok(())
    }
}
