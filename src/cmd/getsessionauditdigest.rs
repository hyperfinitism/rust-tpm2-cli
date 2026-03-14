// SPDX-License-Identifier: Apache-2.0

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

/// Get the session audit digest signed by a key.
///
/// Wraps TPM2_GetSessionAuditDigest (raw FFI).
#[derive(Parser)]
pub struct GetSessionAuditDigestCmd {
    /// Signing key context file path
    #[arg(
        short = 'c',
        long = "signing-key-context",
        conflicts_with = "signing_key_context_handle"
    )]
    pub signing_key_context: Option<PathBuf>,

    /// Signing key handle (hex, e.g. 0x81000001)
    #[arg(long = "signing-key-context-handle", value_parser = parse_hex_u32, conflicts_with = "signing_key_context")]
    pub signing_key_context_handle: Option<u32>,

    /// Auth hierarchy for the privacy admin (e/endorsement)
    #[arg(short = 'C', long = "privacy-admin", default_value = "e")]
    pub privacy_admin: String,

    /// Session context file to audit
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Auth for the signing key
    #[arg(short = 'P', long = "signing-key-auth")]
    pub signing_key_auth: Option<String>,

    /// Auth for the privacy admin hierarchy
    #[arg(short = 'p', long = "hierarchy-auth")]
    pub hierarchy_auth: Option<String>,

    /// Qualifying data (nonce, hex)
    #[arg(short = 'q', long = "qualification")]
    pub qualification: Option<String>,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(long = "signature")]
    pub signature: Option<PathBuf>,
}

impl GetSessionAuditDigestCmd {
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
        let privacy_handle = RawEsysContext::resolve_hierarchy(&self.privacy_admin)?;
        let sign_handle = raw.resolve_handle_from_source(&self.signing_key_context_source()?)?;

        // Load session via raw context_load
        let session_handle = raw.context_load(
            self.session
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid session path"))?,
        )?;

        if let Some(ref auth_str) = self.hierarchy_auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(privacy_handle, auth.value())?;
        }
        if let Some(ref auth_str) = self.signing_key_auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(sign_handle, auth.value())?;
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
            let mut audit_info: *mut TPM2B_ATTEST = std::ptr::null_mut();
            let mut sig: *mut TPMT_SIGNATURE = std::ptr::null_mut();

            let rc = Esys_GetSessionAuditDigest(
                raw.ptr(),
                privacy_handle,
                sign_handle,
                session_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                &qualifying_data,
                &scheme,
                &mut audit_info,
                &mut sig,
            );
            if rc != 0 {
                anyhow::bail!("Esys_GetSessionAuditDigest failed: 0x{rc:08x}");
            }

            if let Some(ref path) = self.attestation {
                raw_esys::write_raw_attestation(audit_info, path)?;
                info!("session audit attestation saved to {}", path.display());
            }
            if let Some(ref path) = self.signature {
                raw_esys::write_raw_signature(sig, path)?;
                info!("signature saved to {}", path.display());
            }

            Esys_Free(audit_info as *mut _);
            Esys_Free(sig as *mut _);
        }

        info!("session audit digest retrieved");
        Ok(())
    }
}
