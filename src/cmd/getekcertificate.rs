// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::interface_types::reserved_handles::NvAuth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;

/// Well-known NV indices for EK certificates (TCG EK Credential Profile).
const NV_RSA_EK_CERT: u32 = 0x01C00002;
const NV_ECC_EK_CERT: u32 = 0x01C0000A;

/// Retrieve the Endorsement Key (EK) certificate from TPM NV storage.
///
/// The TCG EK Credential Profile reserves well-known NV indices for
/// storing EK certificates provisioned during manufacturing:
///   - RSA 2048: 0x01C00002
///   - ECC P-256: 0x01C0000A
///
/// This command reads the certificate from the appropriate NV index
/// and writes it to the specified output file (DER-encoded X.509).
#[derive(Parser)]
pub struct GetEkCertificateCmd {
    /// Key algorithm (rsa, ecc)
    #[arg(short = 'a', long = "algorithm", default_value = "rsa")]
    pub algorithm: String,

    /// Override NV index (hex, e.g. 0x01C00002)
    #[arg(short = 'x', long = "nv-index")]
    pub nv_index: Option<String>,

    /// Output file for the EK certificate (DER-encoded X.509)
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
}

impl GetEkCertificateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let nv_index = match &self.nv_index {
            Some(s) => {
                let stripped = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                u32::from_str_radix(stripped, 16)
                    .map_err(|_| anyhow::anyhow!("invalid NV index: {s}"))?
            }
            None => match self.algorithm.to_lowercase().as_str() {
                "rsa" => NV_RSA_EK_CERT,
                "ecc" => NV_ECC_EK_CERT,
                _ => bail!(
                    "unsupported algorithm '{}'; use 'rsa' or 'ecc'",
                    self.algorithm
                ),
            },
        };

        info!("reading EK certificate from NV index 0x{nv_index:08x}");

        let mut ctx = create_context(global.tcti.as_deref())?;

        let nv_handle = NvIndexTpmHandle::new(nv_index)
            .map_err(|e| anyhow::anyhow!("invalid NV index 0x{nv_index:08x}: {e}"))?;

        // Resolve the NV index to an ESYS_TR.
        let tpm_handle: tss_esapi::handles::TpmHandle = nv_handle.into();
        let nv_idx = ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
            .with_context(|| format!("failed to load NV index 0x{nv_index:08x}"))?;

        // Read the NV public area to determine the certificate size.
        let (nv_public, _) = ctx
            .execute_without_session(|ctx| ctx.nv_read_public(nv_idx.into()))
            .context("TPM2_NV_ReadPublic failed")?;

        let total_size = nv_public.data_size() as u16;
        info!("EK certificate size: {total_size} bytes");

        // Read the certificate data. TPMs often limit NV reads to
        // MAX_NV_BUFFER_SIZE (~1024 bytes), so read in chunks.
        let mut cert_data = Vec::with_capacity(total_size as usize);
        let chunk_size: u16 = 512;
        let mut offset: u16 = 0;

        while offset < total_size {
            let remaining = total_size - offset;
            let to_read = remaining.min(chunk_size);

            let data = ctx
                .execute_with_nullauth_session(|ctx| {
                    ctx.nv_read(NvAuth::Owner, nv_idx.into(), to_read, offset)
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
