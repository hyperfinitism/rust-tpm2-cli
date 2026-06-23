// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::PcrHandle;
use tss_esapi::structures::{Auth, Event};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct PcrEventCmd {
    /// PCR index
    #[arg(value_parser = parse::parse_pcr_handle)]
    pub pcr: PcrHandle,

    /// Authorization value for the PCR (if needed)
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Input data file to hash and extend
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl PcrEventCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(self.pcr.into(), auth.clone())
                .context("failed to set PCR authorization")?;
        }

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;

        let event_data = Event::try_from(data)
            .map_err(|e| anyhow::anyhow!("PCR event input is too large: {e}"))?;
        let digests = execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.pcr_event(self.pcr, event_data.clone())
        })
        .context("TPM2_PCR_Event failed")?;

        info!(
            "PCR {:?} extended with {} digest(s)",
            self.pcr,
            digests.value().len()
        );

        Ok(())
    }
}
