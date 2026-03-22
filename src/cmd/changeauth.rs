// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;

/// Change the authorization value of a TPM object or hierarchy.
///
/// For hierarchies: wraps TPM2_HierarchyChangeAuth.
/// For loaded objects: wraps TPM2_ObjectChangeAuth.
#[derive(Parser)]
pub struct ChangeAuthCmd {
    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "object-context", value_parser = parse_context_source, conflicts_with = "object_context_hierarchy")]
    pub object_context: Option<ContextSource>,

    /// Hierarchy shorthand (o/owner, p/platform, e/endorsement, l/lockout)
    #[arg(long = "object-hierarchy", value_parser = parse::parse_auth_handle, conflicts_with = "object_context")]
    pub object_context_hierarchy: Option<tss_esapi::handles::AuthHandle>,

    /// Parent object context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "parent-context", value_parser = parse_context_source)]
    pub parent_context: Option<ContextSource>,

    /// Current auth value for the object/hierarchy
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// New auth value
    #[arg(short = 'r', long = "new-auth")]
    pub new_auth: String,

    /// Output file for the new private portion (for loaded objects)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl ChangeAuthCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let new_auth = parse::parse_auth(&self.new_auth)?;

        if let Some(auth_handle) = self.object_context_hierarchy {
            if let Some(ref auth_str) = self.auth {
                let auth = parse::parse_auth(auth_str)?;
                ctx.tr_set_auth(auth_handle.into(), auth)
                    .context("tr_set_auth failed")?;
            }

            let session_path = self.session.as_deref();
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.hierarchy_change_auth(auth_handle, new_auth.clone())
            })
            .context("TPM2_HierarchyChangeAuth failed")?;

            info!("hierarchy auth changed");
        } else {
            let object_src = self.object_context.as_ref().ok_or_else(|| {
                anyhow::anyhow!("--object-context or --object-hierarchy is required")
            })?;
            let object_handle = load_object_from_source(&mut ctx, object_src)?;
            let parent_src = self.parent_context.as_ref().ok_or_else(|| {
                anyhow::anyhow!("-C/--parent-context is required for loaded objects")
            })?;
            let parent_handle = load_object_from_source(&mut ctx, parent_src)?;

            if let Some(ref auth_str) = self.auth {
                let auth = parse::parse_auth(auth_str)?;
                ctx.tr_set_auth(object_handle, auth)
                    .context("tr_set_auth failed")?;
            }

            let session_path = self.session.as_deref();
            let new_private = execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.object_change_auth(object_handle, parent_handle, new_auth.clone())
            })
            .context("TPM2_ObjectChangeAuth failed")?;

            if let Some(ref path) = self.output {
                std::fs::write(path, new_private.value())
                    .with_context(|| format!("writing output to {}", path.display()))?;
                info!("new private saved to {}", path.display());
            }

            info!("object auth changed");
        }

        Ok(())
    }
}
