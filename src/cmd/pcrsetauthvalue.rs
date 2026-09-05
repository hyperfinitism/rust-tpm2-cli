// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

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
pub struct PcrSetAuthValueCmd {
    /// PCR index
    #[arg(value_parser = parse::parse_pcr_handle)]
    pub pcr: PcrHandle,

    /// Current authorization value for the PCR
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// New authorization value
    #[arg(short = 'r', long = "new-auth", value_parser = parse::parse_auth)]
    pub new_auth: Auth,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl PcrSetAuthValueCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(self.pcr.into(), auth.clone())
                .context("failed to set PCR authorization")?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.pcr_set_auth_value(self.pcr, self.new_auth.clone())
        })
        .context("TPM2_PCR_SetAuthValue failed")?;

        info!("PCR authorization value changed");
        Ok(())
    }
}
