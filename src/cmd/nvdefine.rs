// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::attributes::NvIndexAttributes;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, NvPublicBuilder};

use tss_esapi::interface_types::reserved_handles::Provision;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse::{self, parse_nv_index};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct NvDefineCmd {
    /// NV index handle (hex, e.g. 0x01400001)
    #[arg(value_parser = parse_nv_index)]
    pub nv_index: NvIndexTpmHandle,

    /// Authorization hierarchy (owner or platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_provision)]
    pub hierarchy: Provision,

    /// Size of the NV area in bytes
    #[arg(short = 's', long = "size", default_value = "0")]
    pub size: u16,

    /// Hash algorithm for the NV index
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub algorithm: HashingAlgorithm,

    /// NV attributes as raw hex or symbolic names
    #[arg(
        short = 'a',
        long = "attributes",
        default_value = "ownerwrite|ownerread",
        value_parser = parse::parse_nv_attributes
    )]
    pub attributes: NvIndexAttributes,

    /// Authorization value for the NV area
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Authorization value for the hierarchy
    #[arg(short = 'P', long = "hierarchy-auth", value_parser = parse::parse_auth)]
    pub hierarchy_auth: Option<Auth>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl NvDefineCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let nv_handle = self.nv_index;

        if let Some(auth) = &self.hierarchy_auth {
            let hierarchy = parse::provision_to_hierarchy_auth(self.hierarchy);
            ctx.tr_set_auth(hierarchy.into(), auth.clone())
                .context("failed to set hierarchy authorization")?;
        }

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_handle)
            .with_index_name_algorithm(self.algorithm)
            .with_index_attributes(self.attributes)
            .with_data_area_size(self.size as usize)
            .build()
            .context("failed to build NvPublic")?;

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.nv_define_space(self.hierarchy, self.auth.clone(), nv_public.clone())
        })
        .context("TPM2_NV_DefineSpace failed")?;

        info!("NV index 0x{:08x} defined", u32::from(self.nv_index));
        Ok(())
    }
}
