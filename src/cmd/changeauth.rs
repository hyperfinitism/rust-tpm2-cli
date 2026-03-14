use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse;
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Change the authorization value of a TPM object or hierarchy.
///
/// For hierarchies: wraps TPM2_HierarchyChangeAuth.
/// For loaded objects: wraps TPM2_ObjectChangeAuth.
#[derive(Parser)]
pub struct ChangeAuthCmd {
    /// Object context file path
    #[arg(short = 'c', long = "object-context", conflicts_with_all = ["object_context_handle", "object_context_hierarchy"])]
    pub object_context: Option<PathBuf>,

    /// Object handle (hex, e.g. 0x81000001)
    #[arg(long = "object-context-handle", value_parser = parse_hex_u32, conflicts_with_all = ["object_context", "object_context_hierarchy"])]
    pub object_context_handle: Option<u32>,

    /// Hierarchy shorthand (o/owner, p/platform, e/endorsement, l/lockout)
    #[arg(long = "object-hierarchy", conflicts_with_all = ["object_context", "object_context_handle"])]
    pub object_context_hierarchy: Option<String>,

    /// Parent object context file path (required for loaded objects, not for hierarchies)
    #[arg(
        short = 'C',
        long = "parent-context",
        conflicts_with = "parent_context_handle"
    )]
    pub parent_context: Option<PathBuf>,

    /// Parent object handle (hex, e.g. 0x81000001)
    #[arg(long = "parent-context-handle", value_parser = parse_hex_u32, conflicts_with = "parent_context")]
    pub parent_context_handle: Option<u32>,

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
    fn object_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.object_context, self.object_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --object-context or --object-context-handle must be provided"
            ),
        }
    }

    fn parent_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.parent_context, self.parent_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --parent-context or --parent-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let new_auth = parse::parse_auth(&self.new_auth)?;

        // Check if this is a hierarchy handle.
        let hierarchy = match &self.object_context_hierarchy {
            Some(h) => match h.to_lowercase().as_str() {
                "o" | "owner" => Some(tss_esapi::handles::AuthHandle::Owner),
                "p" | "platform" => Some(tss_esapi::handles::AuthHandle::Platform),
                "e" | "endorsement" => Some(tss_esapi::handles::AuthHandle::Endorsement),
                "l" | "lockout" => Some(tss_esapi::handles::AuthHandle::Lockout),
                _ => anyhow::bail!("unknown hierarchy shorthand: {h}"),
            },
            None => None,
        };

        if let Some(auth_handle) = hierarchy {
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
            let object_handle = load_object_from_source(&mut ctx, &self.object_context_source()?)?;
            let parent_source = self.parent_context_source().map_err(|_| {
                anyhow::anyhow!(
                    "-C/--parent-context or --parent-context-handle is required for loaded objects"
                )
            })?;
            let parent_handle = load_object_from_source(&mut ctx, &parent_source)?;

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
