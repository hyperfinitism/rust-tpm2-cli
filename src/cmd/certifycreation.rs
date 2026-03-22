// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::structures::Data;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::handle::ContextSource;
use crate::parse::{self, parse_context_source};
use crate::raw_esys::{self, RawEsysContext};

/// Certify the creation data associated with an object.
///
/// Wraps TPM2_CertifyCreation (raw FFI).
#[derive(Parser)]
pub struct CertifyCreationCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "signingkey-context", value_parser = parse_context_source)]
    pub signing_context: ContextSource,

    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "certifiedkey-context", value_parser = parse_context_source)]
    pub certified_context: ContextSource,

    /// Auth value for the signing key
    #[arg(short = 'P', long = "signingkey-auth")]
    pub signing_auth: Option<String>,

    /// Creation hash file
    #[arg(short = 'd', long = "creation-hash")]
    pub creation_hash: PathBuf,

    /// Creation ticket file
    #[arg(short = 't', long = "ticket")]
    pub ticket: PathBuf,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Signature scheme (null)
    #[arg(short = 'g', long = "scheme", default_value = "null")]
    pub scheme: String,

    /// Output file for attestation
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for signature
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,
}

impl CertifyCreationCmd {
    #[allow(clippy::field_reassign_with_default)]
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let sign_handle = raw.resolve_handle_from_source(&self.signing_context)?;
        let obj_handle = raw.resolve_handle_from_source(&self.certified_context)?;

        if let Some(ref auth_str) = self.signing_auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(sign_handle, auth.value())?;
        }

        let creation_hash_data = std::fs::read(&self.creation_hash).with_context(|| {
            format!(
                "reading creation hash from {}",
                self.creation_hash.display()
            )
        })?;
        let mut creation_hash = TPM2B_DIGEST::default();
        let len = creation_hash_data.len().min(creation_hash.buffer.len());
        creation_hash.size = len as u16;
        creation_hash.buffer[..len].copy_from_slice(&creation_hash_data[..len]);

        let ticket_data = std::fs::read(&self.ticket)
            .with_context(|| format!("reading ticket from {}", self.ticket.display()))?;
        // The ticket is a TPMT_TK_CREATION structure. For simplicity, we'll treat
        // it as raw bytes and construct the struct manually if it's the right size.
        let creation_ticket = if ticket_data.len() >= 6 {
            let mut tk = TPMT_TK_CREATION::default();
            // First 2 bytes: tag, next 4 bytes: hierarchy, rest: digest
            tk.tag = u16::from_le_bytes([ticket_data[0], ticket_data[1]]);
            tk.hierarchy = u32::from_le_bytes([
                ticket_data[2],
                ticket_data[3],
                ticket_data[4],
                ticket_data[5],
            ]);
            if ticket_data.len() > 6 {
                let digest_data = &ticket_data[6..];
                let dlen = digest_data.len().min(tk.digest.buffer.len());
                tk.digest.size = dlen as u16;
                tk.digest.buffer[..dlen].copy_from_slice(&digest_data[..dlen]);
            }
            tk
        } else {
            TPMT_TK_CREATION::default()
        };

        let qualifying_data: TPM2B_DATA = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?
                .into(),
            None => TPM2B_DATA::default(),
        };

        let in_scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            ..Default::default()
        };

        unsafe {
            let mut certify_info: *mut TPM2B_ATTEST = std::ptr::null_mut();
            let mut sig: *mut TPMT_SIGNATURE = std::ptr::null_mut();

            let rc = Esys_CertifyCreation(
                raw.ptr(),
                sign_handle,
                obj_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &qualifying_data,
                &creation_hash,
                &in_scheme,
                &creation_ticket,
                &mut certify_info,
                &mut sig,
            );
            if rc != 0 {
                anyhow::bail!("Esys_CertifyCreation failed: 0x{rc:08x}");
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

        info!("certify creation succeeded");
        Ok(())
    }
}
