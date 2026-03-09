use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::handle::ContextSource;
use crate::parse::{self, parse_hex_u32};
use crate::raw_esys::{self, RawEsysContext};

/// Certify the contents of an NV index.
///
/// Wraps TPM2_NV_Certify (raw FFI).
#[derive(Parser)]
pub struct NvCertifyCmd {
    /// Signing key context file path
    #[arg(
        short = 'C',
        long = "signing-key-context",
        conflicts_with = "signing_key_context_handle"
    )]
    pub signing_key_context: Option<PathBuf>,

    /// Signing key handle (hex, e.g. 0x81000001)
    #[arg(long = "signing-key-context-handle", value_parser = parse_hex_u32, conflicts_with = "signing_key_context")]
    pub signing_key_context_handle: Option<u32>,

    /// NV index to certify (hex, e.g. 0x01000001)
    #[arg(short = 'i', long = "nv-index")]
    pub nv_index: String,

    /// Auth hierarchy for the NV index (o/p/e)
    #[arg(short = 'c', long = "nv-auth-hierarchy", default_value = "o")]
    pub nv_auth_hierarchy: String,

    /// Auth value for the signing key
    #[arg(short = 'P', long = "signing-key-auth")]
    pub signing_key_auth: Option<String>,

    /// Auth value for the NV index
    #[arg(short = 'p', long = "nv-auth")]
    pub nv_auth: Option<String>,

    /// Hash algorithm for the signature
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Size of data to certify
    #[arg(short = 's', long = "size", default_value = "0")]
    pub size: u16,

    /// Offset within the NV index
    #[arg(long = "offset", default_value = "0")]
    pub offset: u16,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(long = "signature")]
    pub signature: Option<PathBuf>,

    /// Qualifying data (nonce)
    #[arg(short = 'q', long = "qualification")]
    pub qualification: Option<String>,
}

impl NvCertifyCmd {
    fn signing_key_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.signing_key_context, self.signing_key_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --signing-key-context or --signing-key-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let sign_handle = raw.resolve_handle_from_source(&self.signing_key_context_source()?)?;

        let nv_handle = raw.resolve_nv_index(&self.nv_index)?;

        let auth_handle = if self.nv_auth_hierarchy == "nv" {
            nv_handle
        } else {
            RawEsysContext::resolve_hierarchy(&self.nv_auth_hierarchy)?
        };

        if let Some(ref auth_str) = self.signing_key_auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(sign_handle, auth.value())?;
        }
        if let Some(ref auth_str) = self.nv_auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.value())?;
        }

        let mut qualifying_data = TPM2B_DATA::default();
        if let Some(ref q) = self.qualification {
            let bytes = hex::decode(q).context("invalid qualifying data hex")?;
            qualifying_data.size = bytes.len() as u16;
            qualifying_data.buffer[..bytes.len()].copy_from_slice(&bytes);
        }

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };

        unsafe {
            let mut certify_info: *mut TPM2B_ATTEST = std::ptr::null_mut();
            let mut sig: *mut TPMT_SIGNATURE = std::ptr::null_mut();

            let rc = Esys_NV_Certify(
                raw.ptr(),
                sign_handle,
                auth_handle,
                nv_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                &qualifying_data,
                &scheme,
                self.size,
                self.offset,
                &mut certify_info,
                &mut sig,
            );
            if rc != 0 {
                anyhow::bail!("Esys_NV_Certify failed: 0x{rc:08x}");
            }

            if let Some(ref path) = self.attestation {
                raw_esys::write_raw_attestation(certify_info, path)?;
                info!("attestation saved to {}", path.display());
            }
            if let Some(ref path) = self.signature {
                raw_esys::write_raw_signature(sig, path)?;
                info!("signature saved to {}", path.display());
            }

            Esys_Free(certify_info as *mut _);
            Esys_Free(sig as *mut _);
        }

        info!("NV certify succeeded");
        Ok(())
    }
}
