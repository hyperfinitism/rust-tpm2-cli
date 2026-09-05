// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::reserved_handles::Enables;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct HierarchyControlCmd {
    /// Hierarchy to enable/disable (o/owner, e/endorsement, p/platform, n/null)
    #[arg(value_parser = parse::parse_enables)]
    pub enable: Enables,

    /// Authorization value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Set state (true=enable, false=disable)
    #[arg(short = 's', long = "state", default_value = "true")]
    pub state: bool,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl HierarchyControlCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(AuthHandle::Platform.into(), auth.clone())
                .context("failed to set platform authorization")?;
        }

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.hierarchy_control(self.enable, self.state)
        })
        .context("TPM2_HierarchyControl failed")?;

        info!(
            "hierarchy {:?} {}",
            self.enable,
            if self.state { "enabled" } else { "disabled" }
        );
        Ok(())
    }
}
