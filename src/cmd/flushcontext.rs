use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::constants::CapabilityType;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::structures::CapabilityData;
use tss_esapi::utils::TpmsContext;

use crate::cli::GlobalOpts;
use crate::context::create_context;

const HR_TRANSIENT: u32 = 0x80000000;
const HR_LOADED_SESSION: u32 = 0x02000000;
const HR_SAVED_SESSION: u32 = 0x03000000;

/// Flush a loaded handle from the TPM.
///
/// Supports hex handles, context files, and bulk flags to flush all
/// objects of a given type.
#[derive(Parser)]
pub struct FlushContextCmd {
    /// Context file path to flush
    #[arg(long = "context", conflicts_with_all = ["handle_hex", "transient_object", "loaded_session", "saved_session"])]
    pub handle: Option<PathBuf>,

    /// Hex handle to flush (e.g. 0x80000000)
    #[arg(long = "handle", value_parser = crate::parse::parse_hex_u32, conflicts_with_all = ["handle", "transient_object", "loaded_session", "saved_session"])]
    pub handle_hex: Option<u32>,

    /// Flush all transient objects
    #[arg(long = "transient-object", conflicts_with_all = ["handle", "loaded_session", "saved_session"])]
    pub transient_object: bool,

    /// Flush all loaded sessions
    #[arg(long = "loaded-session", conflicts_with_all = ["handle", "transient_object", "saved_session"])]
    pub loaded_session: bool,

    /// Flush all saved sessions
    #[arg(long = "saved-session", conflicts_with_all = ["handle", "transient_object", "loaded_session"])]
    pub saved_session: bool,
}

impl FlushContextCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        if self.transient_object {
            return flush_all_handles(&mut ctx, HR_TRANSIENT, "transient objects");
        }
        if self.loaded_session {
            return flush_all_handles(&mut ctx, HR_LOADED_SESSION, "loaded sessions");
        }
        if self.saved_session {
            return flush_all_handles(&mut ctx, HR_SAVED_SESSION, "saved sessions");
        }

        if let Some(raw) = self.handle_hex {
            let handle = ObjectHandle::from(raw);
            ctx.flush_context(handle)
                .context("TPM2_FlushContext failed")?;
            info!("flushed handle 0x{raw:08x}");
            return Ok(());
        }

        let path = match &self.handle {
            Some(p) => p,
            None => bail!(
                "provide --context, --handle, or a bulk flush flag (--transient-object, --loaded-session, --saved-session)"
            ),
        };

        let data = std::fs::read(path)
            .with_context(|| format!("reading context file: {}", path.display()))?;
        let saved: TpmsContext =
            serde_json::from_slice(&data).context("failed to deserialize context")?;
        let obj_handle = ctx.context_load(saved).context("context_load failed")?;
        ctx.flush_context(obj_handle)
            .context("TPM2_FlushContext failed")?;
        info!("flushed context from {}", path.display());

        Ok(())
    }
}

fn flush_all_handles(
    ctx: &mut tss_esapi::Context,
    range_start: u32,
    label: &str,
) -> anyhow::Result<()> {
    let handles = get_handles(ctx, range_start)?;

    if handles.is_empty() {
        info!("no {label} to flush");
        return Ok(());
    }

    let mut flushed = 0u32;
    for h in &handles {
        let handle = ObjectHandle::from(*h);
        match ctx.flush_context(handle) {
            Ok(()) => {
                info!("flushed 0x{h:08x}");
                flushed += 1;
            }
            Err(e) => {
                log::warn!("failed to flush 0x{h:08x}: {e}");
            }
        }
    }

    info!("flushed {flushed}/{} {label}", handles.len());
    Ok(())
}

fn get_handles(ctx: &mut tss_esapi::Context, start: u32) -> anyhow::Result<Vec<u32>> {
    let mut all_handles = Vec::new();
    let mut property = start;
    loop {
        let (data, more) = ctx
            .execute_without_session(|ctx| {
                ctx.get_capability(CapabilityType::Handles, property, 254)
            })
            .context("TPM2_GetCapability (handles) failed")?;

        if let CapabilityData::Handles(list) = data {
            let raw: Vec<u32> = list.into_inner().iter().map(|h| u32::from(*h)).collect();
            if let Some(&last) = raw.last() {
                property = last.saturating_add(1);
            }
            all_handles.extend(raw);
        }

        if !more {
            break;
        }
    }

    Ok(all_handles)
}
