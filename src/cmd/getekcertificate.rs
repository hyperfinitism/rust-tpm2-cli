// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{resolve_nv_auth, set_nv_auth};
use crate::output;
use crate::parse::{self, AsymmetricAlgorithm, NvAuthEntity};
use crate::session::{execute_with_command_session, load_command_session};

/// Well-known NV indices for EK certificates (TCG EK Credential Profile).
const NV_RSA_EK_CERT: u32 = 0x01C00002;
const NV_ECC_EK_CERT: u32 = 0x01C0000A;
#[derive(Parser)]
pub struct GetEkCertificateCmd {
    /// Key algorithm (rsa, ecc)
    #[arg(short = 'a', long = "algorithm", default_value = "rsa", value_parser = parse::parse_asymmetric_algorithm)]
    pub algorithm: AsymmetricAlgorithm,

    /// Override NV index (hex, e.g. 0x01C00002)
    #[arg(short = 'x', long = "nv-index", value_parser = parse::parse_nv_index)]
    pub nv_index: Option<NvIndexTpmHandle>,

    /// Authorization entity for the NV index (owner, platform, or nv-index)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_nv_auth_entity)]
    pub hierarchy: NvAuthEntity,

    /// Authorization value for the NV index
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Output file for the EK certificate (DER-encoded X.509)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,

    /// Maximum bytes requested by each TPM2_NV_Read call
    #[arg(long = "chunk-size", default_value = "512", value_parser = clap::value_parser!(u16).range(1..))]
    pub chunk_size: u16,
}

impl GetEkCertificateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let nv_handle = self.nv_index.unwrap_or_else(|| {
            NvIndexTpmHandle::new(match self.algorithm {
                AsymmetricAlgorithm::Rsa => NV_RSA_EK_CERT,
                AsymmetricAlgorithm::Ecc => NV_ECC_EK_CERT,
            })
            .expect("TCG EK certificate indices are valid NV handles")
        });
        let nv_index = u32::from(nv_handle);

        info!("reading EK certificate from NV index 0x{nv_index:08x}");

        let mut ctx = create_context(global.tcti.as_ref())?;

        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .with_context(|| format!("failed to load NV index 0x{nv_index:08x}"))?;
        let nv_auth = resolve_nv_auth(&mut ctx, self.hierarchy, nv_handle)?;
        if let Some(auth) = &self.auth {
            set_nv_auth(&mut ctx, nv_auth, auth.clone())?;
        }
        let (nv_public, _) = ctx
            .execute_without_session(|ctx| ctx.nv_read_public(nv_idx.into()))
            .context("TPM2_NV_ReadPublic failed")?;

        let total_size = nv_public.data_size() as u16;
        info!("EK certificate size: {total_size} bytes");
        let mut cert_data = Vec::with_capacity(total_size as usize);
        let mut offset: u16 = 0;
        let session = load_command_session(&mut ctx, self.session.as_deref())?;

        while offset < total_size {
            let remaining = total_size - offset;
            let to_read = remaining.min(self.chunk_size);

            let data = execute_with_command_session(&mut ctx, session, |ctx| {
                ctx.nv_read(nv_auth, nv_idx.into(), to_read, offset)
            })
            .with_context(|| format!("TPM2_NV_Read failed at offset {offset}"))?;

            cert_data.extend_from_slice(data.as_bytes());
            offset += to_read;
        }

        if let Some(ref path) = self.output {
            output::write_to_file(path, &cert_data)?;
            info!(
                "EK certificate ({}) saved to {} ({} bytes)",
                self.algorithm,
                path.display(),
                cert_data.len()
            );
        } else {
            output::print_hex(&cert_data);
        }

        Ok(())
    }
}
