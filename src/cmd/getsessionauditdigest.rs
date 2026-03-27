// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::structures::{Auth, Data};
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::handle::ContextSource;
use crate::parse::{self, parse_context_source};
use crate::raw_esys::{self, RawEsysContext};

/// Get the session audit digest signed by a key.
///
/// Wraps TPM2_GetSessionAuditDigest (raw FFI).
#[derive(Parser)]
pub struct GetSessionAuditDigestCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "signing-key-context", value_parser = parse_context_source)]
    pub signing_key_context: ContextSource,

    /// Auth hierarchy for the privacy admin (e/endorsement)
    #[arg(short = 'C', long = "privacy-admin", default_value = "e", value_parser = parse::parse_esys_hierarchy)]
    pub privacy_admin: u32,

    /// Session context file to audit
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Auth for the signing key
    #[arg(short = 'P', long = "signing-key-auth", value_parser = parse::parse_auth)]
    pub signing_key_auth: Option<Auth>,

    /// Auth for the privacy admin hierarchy
    #[arg(short = 'p', long = "hierarchy-auth", value_parser = parse::parse_auth)]
    pub hierarchy_auth: Option<Auth>,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = crate::parse::parse_qualification)]
    pub qualification: Option<crate::parse::Qualification>,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(long = "signature")]
    pub signature: Option<PathBuf>,
}

impl GetSessionAuditDigestCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let privacy_handle = self.privacy_admin;
        let sign_handle = raw.resolve_handle_from_source(&self.signing_key_context)?;

        // Load session via raw context_load
        let session_handle = raw.context_load(
            self.session
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid session path"))?,
        )?;

        if let Some(ref auth) = self.hierarchy_auth {
            raw.set_auth(privacy_handle, auth.as_bytes())?;
        }
        if let Some(ref auth) = self.signing_key_auth {
            raw.set_auth(sign_handle, auth.as_bytes())?;
        }

        let qualifying_data: TPM2B_DATA = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
                .into(),
            None => TPM2B_DATA::default(),
        };

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
