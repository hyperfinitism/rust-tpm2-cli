// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use log::info;

use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_policy_or_hmac_session;
#[derive(Parser)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["object_context", "object_context_hierarchy"])
))]
pub struct ChangeAuthCmd {
    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "object-context", value_parser = parse_context_source, requires = "parent_context")]
    pub object_context: Option<ContextSource>,

    /// Hierarchy shorthand (o/owner, p/platform, e/endorsement, l/lockout)
    #[arg(long = "object-hierarchy", value_parser = parse::parse_auth_handle)]
    pub object_context_hierarchy: Option<tss_esapi::handles::AuthHandle>,

    /// Parent object context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "parent-context", value_parser = parse_context_source, requires = "object_context")]
    pub parent_context: Option<ContextSource>,

    /// Current authorization value for the object/hierarchy
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// New authorization value
    #[arg(short = 'r', long = "new-auth", value_parser = parse::parse_auth)]
    pub new_auth: Auth,

    /// Output file for the new private portion (for loaded objects)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// HMAC session context file for authorization
    #[arg(short = 'S', long = "session", conflicts_with = "policy_session")]
    pub session: Option<PathBuf>,

    /// Policy session context file for authorization
    #[arg(long = "policy-session", conflicts_with = "session")]
    pub policy_session: Option<PathBuf>,
}

impl ChangeAuthCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if let Some(auth_handle) = self.object_context_hierarchy {
            if let Some(ref auth) = self.auth {
                ctx.tr_set_auth(auth_handle.into(), auth.clone())
                    .context("tr_set_auth failed")?;
            }

            execute_with_optional_policy_or_hmac_session(
                &mut ctx,
                self.policy_session.as_deref(),
                self.session.as_deref(),
                |ctx| ctx.hierarchy_change_auth(auth_handle, self.new_auth.clone()),
            )
            .context("TPM2_HierarchyChangeAuth failed")?;

            info!("hierarchy auth changed");
        } else {
            let object_src = self
                .object_context
                .as_ref()
                .expect("clap requires exactly one target");
            let object_handle = load_object_from_source(&mut ctx, object_src)?;
            let parent_src = self
                .parent_context
                .as_ref()
                .expect("clap requires a parent for an object target");
            let parent_handle = load_object_from_source(&mut ctx, parent_src)?;

            if let Some(ref auth) = self.auth {
                ctx.tr_set_auth(object_handle, auth.clone())
                    .context("tr_set_auth failed")?;
            }

            let new_private = execute_with_optional_policy_or_hmac_session(
                &mut ctx,
                self.policy_session.as_deref(),
                self.session.as_deref(),
                |ctx| ctx.object_change_auth(object_handle, parent_handle, self.new_auth.clone()),
            )
            .context("TPM2_ObjectChangeAuth failed")?;

            if let Some(ref path) = self.output {
                std::fs::write(path, new_private.as_bytes())
                    .with_context(|| format!("writing output to {}", path.display()))?;
                info!("new private saved to {}", path.display());
            }

            info!("object auth changed");
        }

        Ok(())
    }
}
