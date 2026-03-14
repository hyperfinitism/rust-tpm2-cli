// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::PersistentTpmHandle;
use tss_esapi::interface_types::dynamic_handles::Persistent;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_hex_u32};
use crate::session::execute_with_optional_session;

/// Make a transient object persistent, or evict a persistent object.
///
/// When making persistent, pass the transient handle as `-c` and the desired
/// persistent handle as the positional argument.
#[derive(Parser)]
pub struct EvictControlCmd {
    /// Persistent handle (hex, e.g. 0x81000001)
    #[arg(value_parser = parse_hex_u32)]
    pub persistent_handle: u32,

    /// Transient object context file
    #[arg(short = 'c', long = "context", conflicts_with = "context_handle")]
    pub context: Option<PathBuf>,

    /// Transient object handle (hex, e.g. 0x80000001)
    #[arg(long = "context-handle", value_parser = parse_hex_u32, conflicts_with = "context")]
    pub context_handle: Option<u32>,

    /// Authorization hierarchy (o/owner, p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl EvictControlCmd {
    fn context_source(&self) -> Option<anyhow::Result<ContextSource>> {
        match (&self.context, self.context_handle) {
            (Some(path), None) => Some(Ok(ContextSource::File(path.clone()))),
            (None, Some(handle)) => Some(Ok(ContextSource::Handle(handle))),
            (None, None) => None,
            _ => Some(Err(anyhow::anyhow!(
                "only one of --context or --context-handle may be provided"
            ))),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let provision = parse::parse_provision(&self.hierarchy)?;
        let persistent_tpm_handle = PersistentTpmHandle::new(self.persistent_handle)
            .map_err(|e| anyhow::anyhow!("invalid persistent handle: {e}"))?;
        let persistent: Persistent = persistent_tpm_handle.into();

        let session_path = self.session.as_deref();

        // If a transient context is given, make it persistent
        if let Some(source_result) = self.context_source() {
            let source = source_result?;
            let obj_handle = load_object_from_source(&mut ctx, &source)?;
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.evict_control(provision, obj_handle, persistent)
            })
            .context("TPM2_EvictControl failed")?;
            info!(
                "object persisted at 0x{:08x}",
                u32::from(persistent_tpm_handle)
            );
        } else {
            // Evict the persistent object
            let tpm_handle: tss_esapi::handles::TpmHandle = persistent_tpm_handle.into();
            let obj = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
                .context("failed to load persistent handle")?;
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.evict_control(provision, obj, persistent)
            })
            .context("TPM2_EvictControl (evict) failed")?;
            info!(
                "persistent object 0x{:08x} evicted",
                u32::from(persistent_tpm_handle)
            );
        }

        Ok(())
    }
}
