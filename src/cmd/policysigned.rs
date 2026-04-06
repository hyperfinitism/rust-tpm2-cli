// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::Signature;
use tss_esapi::traits::UnMarshall;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse::{self, parse_context_source};
use crate::raw_esys::RawEsysContext;

use crate::handle::ContextSource;

/// Extend a policy with PolicySigned.
///
/// Wraps TPM2_PolicySigned (raw FFI). PolicySigned uses no
/// authorization sessions because the command has no authIndex.
/// Instead, the TPM validates the provided signature against
/// authObject's public key as part of the policy assertion.
#[derive(Parser)]
pub struct PolicySignedCmd {
    /// Policy session file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Signature file (marshaled TPMT_SIGNATURE)
    #[arg(short = 's', long = "signature")]
    pub signature: PathBuf,

    /// Expiration time in seconds (0 = no expiration)
    #[arg(short = 'x', long = "expiration", default_value = "0")]
    pub expiration: i32,

    /// cpHash file (optional)
    #[arg(long = "cphash-input")]
    pub cphash_input: Option<PathBuf>,

    /// Policy reference (digest) (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Output file for the timeout
    #[arg(short = 't', long = "timeout")]
    pub timeout_out: Option<PathBuf>,

    /// Output file for the policy ticket
    #[arg(long = "ticket")]
    pub ticket_out: Option<PathBuf>,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: Option<PathBuf>,
}

impl PolicySignedCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        let session_handle = raw.context_load(
            self.session
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid session path"))?,
        )?;

        let auth_object = raw.resolve_handle_from_source(&self.key_context)?;

        let sig_data = std::fs::read(&self.signature)
            .with_context(|| format!("reading signature from {}", self.signature.display()))?;
        let signature = Signature::unmarshall(&sig_data)
            .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;
        let tpmt_sig: TPMT_SIGNATURE = signature
            .try_into()
            .map_err(|e| anyhow::anyhow!("signature conversion: {e:?}"))?;

        let nonce_tpm = TPM2B_NONCE::default();

        let cp_hash = match &self.cphash_input {
            Some(path) => {
                let data = std::fs::read(path)?;
                let mut buf = TPM2B_DIGEST::default();
                if data.len() > buf.buffer.len() {
                    anyhow::bail!(
                        "cpHash from {} is too large: {} bytes (maximum {} bytes)",
                        path.display(),
                        data.len(),
                        buf.buffer.len()
                    );
                }
                buf.size = data.len() as u16;
                buf.buffer[..data.len()].copy_from_slice(&data);
                buf
            }
            None => TPM2B_DIGEST::default(),
        };

        let policy_ref = match &self.qualification {
            Some(q) => {
                let data = q.as_slice();
                let mut buf = TPM2B_NONCE::default();
                if data.len() > buf.buffer.len() {
                    anyhow::bail!(
                        "qualification is too large: {} bytes (maximum {} bytes)",
                        data.len(),
                        buf.buffer.len()
                    );
                }
                buf.size = data.len() as u16;
                buf.buffer[..data.len()].copy_from_slice(data);
                buf
            }
            None => TPM2B_NONCE::default(),
        };

        // Extract data from ESYS-allocated pointers immediately, then free
        // them before performing any I/O that could fail and leak memory.
        let (timeout_data, ticket_data) = unsafe {
            let mut timeout_ptr: *mut TPM2B_TIMEOUT = std::ptr::null_mut();
            let mut ticket_ptr: *mut TPMT_TK_AUTH = std::ptr::null_mut();

            // PolicySigned has Auth Index: None for both handles,
            // so all session handles are ESYS_TR_NONE.
            let rc = Esys_PolicySigned(
                raw.ptr(),
                auth_object,
                session_handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &nonce_tpm,
                &cp_hash,
                &policy_ref,
                self.expiration,
                &tpmt_sig,
                &mut timeout_ptr,
                &mut ticket_ptr,
            );
            if rc != 0 {
                anyhow::bail!("Esys_PolicySigned failed: 0x{rc:08x}");
            }

            let timeout_data = if !timeout_ptr.is_null() {
                let t = &*timeout_ptr;
                Some(t.buffer[..t.size as usize].to_vec())
            } else {
                None
            };

            let ticket_data = if !ticket_ptr.is_null() {
                let ticket = &*ticket_ptr;
                let bytes = std::slice::from_raw_parts(
                    ticket as *const TPMT_TK_AUTH as *const u8,
                    std::mem::size_of::<TPMT_TK_AUTH>(),
                );
                Some(bytes.to_vec())
            } else {
                None
            };

            if !timeout_ptr.is_null() {
                Esys_Free(timeout_ptr as *mut _);
            }
            if !ticket_ptr.is_null() {
                Esys_Free(ticket_ptr as *mut _);
            }

            (timeout_data, ticket_data)
        };

        if let (Some(path), Some(data)) = (&self.timeout_out, &timeout_data) {
            std::fs::write(path, data)
                .with_context(|| format!("writing timeout to {}", path.display()))?;
        }

        if let (Some(path), Some(data)) = (&self.ticket_out, &ticket_data) {
            std::fs::write(path, data)
                .with_context(|| format!("writing ticket to {}", path.display()))?;
        }

        if let Some(ref path) = self.policy {
            let digest_data = unsafe {
                let mut digest_ptr: *mut TPM2B_DIGEST = std::ptr::null_mut();
                let rc = Esys_PolicyGetDigest(
                    raw.ptr(),
                    session_handle,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &mut digest_ptr,
                );
                if rc != 0 {
                    anyhow::bail!("Esys_PolicyGetDigest failed: 0x{rc:08x}");
                }

                if !digest_ptr.is_null() {
                    let d = &*digest_ptr;
                    let v = d.buffer[..d.size as usize].to_vec();
                    Esys_Free(digest_ptr as *mut _);
                    Some(v)
                } else {
                    None
                }
            };
            if let Some(ref data) = digest_data {
                std::fs::write(path, data)
                    .with_context(|| format!("writing policy digest to {}", path.display()))?;
            }
        }

        raw.context_save_to_file(session_handle, &self.session)?;
        info!("policy signed succeeded");
        Ok(())
    }
}
