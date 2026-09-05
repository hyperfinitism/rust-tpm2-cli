// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::{ArgGroup, Parser};
use log::info;
use tss_esapi::constants::CapabilityType;
use tss_esapi::handles::TpmHandle;
use tss_esapi::structures::CapabilityData;
use tss_esapi::structures::SavedTpmContext;

use crate::cli::GlobalOpts;
use crate::context::create_context;

const HR_TRANSIENT: u32 = 0x80000000;
const HR_LOADED_SESSION: u32 = 0x02000000;
const HR_SAVED_SESSION: u32 = 0x03000000;
#[derive(Parser)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["handle", "handle_hex", "transient_object", "loaded_session", "saved_session"])
))]
pub struct FlushContextCmd {
    /// Context file path to flush
    #[arg(long = "context")]
    pub handle: Option<PathBuf>,

    /// Hex handle to flush (e.g. 0x80000000)
    #[arg(long = "handle", value_parser = crate::parse::parse_tpm_handle)]
    pub handle_hex: Option<tss_esapi::handles::TpmHandle>,

    /// Flush all transient objects
    #[arg(long = "transient-object")]
    pub transient_object: bool,

    /// Flush all loaded sessions
    #[arg(long = "loaded-session")]
    pub loaded_session: bool,

    /// Flush all saved sessions
    #[arg(long = "saved-session")]
    pub saved_session: bool,

    /// Maximum handles requested per capability query during bulk flush
    #[arg(short = 'n', long = "count", default_value = "254", value_parser = clap::value_parser!(u32).range(1..))]
    pub count: u32,
}

impl FlushContextCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        if self.transient_object {
            return flush_all_handles(&mut ctx, HR_TRANSIENT, self.count, "transient objects");
        }
        if self.loaded_session {
            return flush_all_handles(&mut ctx, HR_LOADED_SESSION, self.count, "loaded sessions");
        }
        if self.saved_session {
            return flush_all_handles(&mut ctx, HR_SAVED_SESSION, self.count, "saved sessions");
        }

        if let Some(tpm_handle) = self.handle_hex {
            let raw = u32::from(tpm_handle);
            let handle = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
                .context("failed to resolve TPM handle")?;
            ctx.flush_context(handle)
                .context("TPM2_FlushContext failed")?;
            info!("flushed handle 0x{raw:08x}");
            return Ok(());
        }

        let path = self
            .handle
            .as_ref()
            .expect("clap requires exactly one flush target");

        let data = std::fs::read(path)
            .with_context(|| format!("reading context file: {}", path.display()))?;
        let saved: SavedTpmContext =
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
    count: u32,
    label: &str,
) -> anyhow::Result<()> {
    let handles = get_handles(ctx, range_start, count)?;

    if handles.is_empty() {
        info!("no {label} to flush");
        return Ok(());
    }

    let mut flushed = 0u32;
    for tpm_handle in &handles {
        let raw = u32::from(*tpm_handle);
        let result = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(*tpm_handle))
            .and_then(|handle| ctx.flush_context(handle));
        match result {
            Ok(()) => {
                info!("flushed 0x{raw:08x}");
                flushed += 1;
            }
            Err(e) => {
                log::warn!("failed to flush 0x{raw:08x}: {e}");
            }
        }
    }

    info!("flushed {flushed}/{} {label}", handles.len());
    Ok(())
}

fn get_handles(
    ctx: &mut tss_esapi::Context,
    start: u32,
    count: u32,
) -> anyhow::Result<Vec<TpmHandle>> {
    let mut all_handles = Vec::new();
    let mut property = start;
    loop {
        let (data, more) = ctx
            .execute_without_session(|ctx| {
                ctx.get_capability(CapabilityType::Handles, property, count)
            })
            .context("TPM2_GetCapability (handles) failed")?;

        if let CapabilityData::Handles(list) = data {
            let handles = list.into_inner();
            if let Some(last) = handles.last() {
                property = u32::from(*last).saturating_add(1);
            }
            all_handles.extend(handles);
        }

        if !more {
            break;
        }
    }

    Ok(all_handles)
}
