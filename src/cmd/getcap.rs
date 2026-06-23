// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use serde_json::{Value, json};

use tss_esapi::constants::CapabilityType;
use tss_esapi::structures::CapabilityData;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse::{self, CapabilityQuery};
const PT_FIXED_START: u32 = 0x100; // TPM2_PT_FIXED
const PT_VAR_START: u32 = 0x200; // TPM2_PT_VAR
const CC_FIRST: u32 = 0x011F; // TPM2_CC_FIRST
const ALG_FIRST: u32 = 0x0001; // TPM2_ALG_FIRST
const HR_PCR: u32 = 0x00000000;
const HR_NV_INDEX: u32 = 0x01000000;
const HR_LOADED_SESSION: u32 = 0x02000000;
const HR_SAVED_SESSION: u32 = 0x03000000;
const HR_PERMANENT: u32 = 0x40000000;
const HR_TRANSIENT: u32 = 0x80000000;
const HR_PERSISTENT: u32 = 0x81000000;

const ALL_CAPS: &[&str] = &[
    "algorithms",
    "commands",
    "pcrs",
    "properties-fixed",
    "properties-variable",
    "ecc-curves",
    "handles-transient",
    "handles-persistent",
    "handles-permanent",
    "handles-pcr",
    "handles-nv-index",
    "handles-loaded-session",
    "handles-saved-session",
];
#[derive(Parser)]
pub struct GetCapCmd {
    /// Capability to query (e.g. algorithms, properties-fixed, handles-persistent)
    #[arg(required_unless_present = "list", value_parser = parse::parse_capability_query)]
    pub capability: Option<CapabilityQuery>,

    /// List all supported capability names
    #[arg(short = 'l', long = "list")]
    pub list: bool,

    /// Maximum number of capability entries requested per TPM call
    #[arg(short = 'n', long = "count", default_value = "254", value_parser = clap::value_parser!(u32).range(1..))]
    pub count: u32,
}

impl GetCapCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        if self.list {
            for cap in ALL_CAPS {
                println!("{cap}");
            }
            return Ok(());
        }

        let cap = self
            .capability
            .expect("clap requires a capability unless --list is present");
        let mut ctx = create_context(global.tcti.as_ref())?;

        let value = match cap {
            CapabilityQuery::Algorithms => query_algorithms(&mut ctx, self.count)?,
            CapabilityQuery::Commands => query_commands(&mut ctx, self.count)?,
            CapabilityQuery::Pcrs => query_pcrs(&mut ctx, self.count)?,
            CapabilityQuery::PropertiesFixed => {
                query_properties(&mut ctx, PT_FIXED_START, self.count)?
            }
            CapabilityQuery::PropertiesVariable => {
                query_properties(&mut ctx, PT_VAR_START, self.count)?
            }
            CapabilityQuery::EccCurves => query_ecc_curves(&mut ctx, self.count)?,
            CapabilityQuery::HandlesTransient => query_handles(&mut ctx, HR_TRANSIENT, self.count)?,
            CapabilityQuery::HandlesPersistent => {
                query_handles(&mut ctx, HR_PERSISTENT, self.count)?
            }
            CapabilityQuery::HandlesPermanent => query_handles(&mut ctx, HR_PERMANENT, self.count)?,
            CapabilityQuery::HandlesPcr => query_handles(&mut ctx, HR_PCR, self.count)?,
            CapabilityQuery::HandlesNvIndex => query_handles(&mut ctx, HR_NV_INDEX, self.count)?,
            CapabilityQuery::HandlesLoadedSession => {
                query_handles(&mut ctx, HR_LOADED_SESSION, self.count)?
            }
            CapabilityQuery::HandlesSavedSession => {
                query_handles(&mut ctx, HR_SAVED_SESSION, self.count)?
            }
        };

        println!("{}", serde_json::to_string_pretty(&value)?);
        Ok(())
    }
}

/// Fetch all capability data by looping while the TPM sets more_data.
fn fetch_all(
    ctx: &mut tss_esapi::Context,
    cap_type: CapabilityType,
    start: u32,
    count: u32,
) -> anyhow::Result<Vec<CapabilityData>> {
    let mut results = Vec::new();
    let mut property = start;
    loop {
        let (data, more) = ctx
            .execute_without_session(|ctx| ctx.get_capability(cap_type, property, count))
            .context("TPM2_GetCapability failed")?;
        let last = last_property_u32(&data);
        results.push(data);
        if !more {
            break;
        }
        match last {
            Some(p) => property = p.saturating_add(1),
            None => break,
        }
    }
    Ok(results)
}

/// Return the discriminant value of the last element in a capability chunk.
/// Used to compute the start property for the next call when more_data is set.
fn last_property_u32(data: &CapabilityData) -> Option<u32> {
    match data {
        CapabilityData::Algorithms(list) => list.last().map(|a| a.algorithm_identifier() as u32),
        CapabilityData::Handles(list) => list.last().map(|h| u32::from(*h)),
        CapabilityData::Commands(list) => list.last().map(|c| c.command_index() as u32),
        CapabilityData::TpmProperties(list) => list.last().map(|p| p.property() as u32),
        CapabilityData::EccCurves(list) => list.last().map(|c| *c as u32),
        _ => None,
    }
}

fn query_algorithms(ctx: &mut tss_esapi::Context, count: u32) -> anyhow::Result<Value> {
    let chunks = fetch_all(ctx, CapabilityType::Algorithms, ALG_FIRST, count)?;
    let mut arr = Vec::new();
    for chunk in chunks {
        if let CapabilityData::Algorithms(list) = chunk {
            for alg in list {
                let attrs = alg.algorithm_properties();
                arr.push(json!({
                    "algorithm": format!("{:?}", alg.algorithm_identifier()),
                    "asymmetric": attrs.asymmetric(),
                    "symmetric": attrs.symmetric(),
                    "hash": attrs.hash(),
                    "object": attrs.object(),
                    "signing": attrs.signing(),
                    "encrypting": attrs.encrypting(),
                    "method": attrs.method(),
                }));
            }
        }
    }
    Ok(Value::Array(arr))
}

fn query_commands(ctx: &mut tss_esapi::Context, count: u32) -> anyhow::Result<Value> {
    let chunks = fetch_all(ctx, CapabilityType::Command, CC_FIRST, count)?;
    let mut arr = Vec::new();
    for chunk in chunks {
        if let CapabilityData::Commands(list) = chunk {
            for cmd in list {
                arr.push(json!({
                    "command": format!("0x{:04x}", cmd.command_index()),
                    "nv": cmd.nv(),
                    "extensive": cmd.extensive(),
                    "flushed": cmd.flushed(),
                    "handles": cmd.c_handles(),
                    "r_handle": cmd.r_handle(),
                    "vendor_specific": cmd.is_vendor_specific(),
                }));
            }
        }
    }
    Ok(Value::Array(arr))
}

fn query_pcrs(ctx: &mut tss_esapi::Context, count: u32) -> anyhow::Result<Value> {
    let chunks = fetch_all(ctx, CapabilityType::AssignedPcr, 0, count)?;
    let mut map = serde_json::Map::new();
    for chunk in chunks {
        if let CapabilityData::AssignedPcr(psl) = chunk {
            for sel in psl.get_selections() {
                let alg = format!("{:?}", sel.hashing_algorithm());
                let indices: Vec<Value> = sel
                    .selected()
                    .iter()
                    .map(|s| Value::Number((u32::from(*s).trailing_zeros() as u64).into()))
                    .collect();
                map.insert(alg, Value::Array(indices));
            }
        }
    }
    Ok(Value::Object(map))
}

fn query_properties(ctx: &mut tss_esapi::Context, start: u32, count: u32) -> anyhow::Result<Value> {
    let chunks = fetch_all(ctx, CapabilityType::TpmProperties, start, count)?;
    let mut arr = Vec::new();
    for chunk in chunks {
        if let CapabilityData::TpmProperties(list) = chunk {
            for prop in list {
                arr.push(json!({
                    "property": format!("{:?}", prop.property()),
                    "value": prop.value(),
                }));
            }
        }
    }
    Ok(Value::Array(arr))
}

fn query_ecc_curves(ctx: &mut tss_esapi::Context, count: u32) -> anyhow::Result<Value> {
    let chunks = fetch_all(ctx, CapabilityType::EccCurves, 0, count)?;
    let mut arr = Vec::new();
    for chunk in chunks {
        if let CapabilityData::EccCurves(list) = chunk {
            for curve in list.into_inner() {
                arr.push(Value::String(format!("{:?}", curve)));
            }
        }
    }
    Ok(Value::Array(arr))
}

fn query_handles(ctx: &mut tss_esapi::Context, start: u32, count: u32) -> anyhow::Result<Value> {
    let chunks = fetch_all(ctx, CapabilityType::Handles, start, count)?;
    let mut arr = Vec::new();
    for chunk in chunks {
        if let CapabilityData::Handles(list) = chunk {
            for h in list.into_inner() {
                arr.push(Value::String(format!("0x{:08x}", u32::from(h))));
            }
        }
    }
    Ok(Value::Array(arr))
}
