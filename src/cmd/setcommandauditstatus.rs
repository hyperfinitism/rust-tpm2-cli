// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, CommandCodeList};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct SetCommandAuditStatusCmd {
    /// Authorization hierarchy (owner or platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_owner_or_platform_auth_handle)]
    pub hierarchy: AuthHandle,

    /// Authorization value
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Hash algorithm for the audit digest
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Command codes to set for audit (comma-separated hex)
    #[arg(long = "set-list", value_parser = parse::parse_command_code_list)]
    pub set_list: Option<CommandCodeList>,

    /// Command codes to clear from audit (comma-separated hex)
    #[arg(long = "clear-list", value_parser = parse::parse_command_code_list)]
    pub clear_list: Option<CommandCodeList>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<std::path::PathBuf>,
}

impl SetCommandAuditStatusCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(self.hierarchy.into(), auth.clone())
                .context("failed to set hierarchy authorization")?;
        }

        let set_list = self.set_list.clone().unwrap_or_default();
        let clear_list = self.clear_list.clone().unwrap_or_default();

        execute_with_optional_session(&mut ctx, self.session.as_deref(), |ctx| {
            ctx.set_command_code_audit_status(
                self.hierarchy,
                self.hash_algorithm,
                set_list,
                clear_list,
            )
        })
        .context("TPM2_SetCommandCodeAuditStatus failed")?;

        info!("command audit status updated");
        Ok(())
    }
}
