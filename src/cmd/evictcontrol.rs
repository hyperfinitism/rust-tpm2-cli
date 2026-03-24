// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::PersistentTpmHandle;
use tss_esapi::interface_types::data_handles::Persistent;

use tss_esapi::interface_types::reserved_handles::Provision;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source, parse_hex_u32};
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

    /// Transient object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: Option<ContextSource>,

    /// Authorization hierarchy (o/owner, p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_provision)]
    pub hierarchy: Provision,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl EvictControlCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let persistent_tpm_handle = PersistentTpmHandle::new(self.persistent_handle)
            .map_err(|e| anyhow::anyhow!("invalid persistent handle: {e}"))?;
        let persistent: Persistent = persistent_tpm_handle.into();

        let session_path = self.session.as_deref();

        // If a transient context is given, make it persistent
        if let Some(ref source) = self.context {
            let obj_handle = load_object_from_source(&mut ctx, source)?;
            execute_with_optional_session(&mut ctx, session_path, |ctx| {
                ctx.evict_control(self.hierarchy, obj_handle, persistent)
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
                ctx.evict_control(self.hierarchy, obj, persistent)
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
