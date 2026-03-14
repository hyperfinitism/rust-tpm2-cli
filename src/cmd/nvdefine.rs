use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::structures::NvPublicBuilder;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse::{self, parse_hex_u32};
use crate::session::execute_with_optional_session;

/// Define a new NV index.
#[derive(Parser)]
pub struct NvDefineCmd {
    /// NV index handle (hex, e.g. 0x01400001)
    #[arg(value_parser = parse_hex_u32)]
    pub nv_index: u32,

    /// Authorization hierarchy (o/owner, p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Size of the NV area in bytes
    #[arg(short = 's', long = "size", default_value = "0")]
    pub size: u16,

    /// Hash algorithm for the NV index
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub algorithm: String,

    /// NV attributes as raw hex or symbolic names
    #[arg(
        short = 'a',
        long = "attributes",
        default_value = "ownerwrite|ownerread"
    )]
    pub attributes: String,

    /// Authorization value for the NV area
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl NvDefineCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let provision = parse::parse_provision(&self.hierarchy)?;
        let nv_handle = NvIndexTpmHandle::new(self.nv_index)
            .map_err(|e| anyhow::anyhow!("invalid NV index handle: {e}"))?;
        let alg = parse::parse_hashing_algorithm(&self.algorithm)?;

        let nv_attributes = parse::parse_nv_attributes(&self.attributes)?;

        let auth = match &self.auth {
            Some(a) => Some(parse::parse_auth(a)?),
            None => None,
        };

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_handle)
            .with_index_name_algorithm(alg)
            .with_index_attributes(nv_attributes)
            .with_data_area_size(self.size as usize)
            .build()
            .context("failed to build NvPublic")?;

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.nv_define_space(provision, auth.clone(), nv_public.clone())
        })
        .context("TPM2_NV_DefineSpace failed")?;

        info!("NV index 0x{:08x} defined", self.nv_index);
        Ok(())
    }
}
