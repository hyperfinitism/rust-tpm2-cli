// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct PcrExtendCmd {
    /// PCR extension specification
    #[arg(value_parser = parse::parse_pcr_extend_argument)]
    pub extend_spec: parse::PcrExtendArgument,

    /// Authorization value for the PCR
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl PcrExtendCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(self.extend_spec.pcr_handle().into(), auth.clone())
                .context("failed to set PCR authorization")?;
        }

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.pcr_extend(
                self.extend_spec.pcr_handle(),
                self.extend_spec.digest_values().clone(),
            )
        })
        .context("TPM2_PCR_Extend failed")?;

        info!("PCR {} extended", self.extend_spec.pcr_index());
        Ok(())
    }
}
