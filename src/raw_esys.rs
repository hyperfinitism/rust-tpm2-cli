// SPDX-License-Identifier: Apache-2.0

//! Raw ESYS FFI wrappers for TPM2 commands not yet in tss-esapi.
//!
//! This module calls the C ESAPI functions directly through tss-esapi-sys,
//! managing its own raw `ESYS_CONTEXT`.

use std::ffi::CString;
use std::ptr::null_mut;

use anyhow::bail;
use tss_esapi::tss2_esys::*;

use crate::tcti::{TctiConfig, default_tcti};

/// A thin RAII wrapper around a raw `ESYS_CONTEXT*`.
pub(crate) struct RawEsysContext {
    ctx: *mut ESYS_CONTEXT,
}

impl RawEsysContext {
    /// Create a new raw ESYS context from a TCTI config string.
    pub(crate) fn new(tcti: Option<&TctiConfig>) -> anyhow::Result<Self> {
        let default;
        let tcti = match tcti {
            Some(tcti) => tcti,
            None => {
                default = default_tcti();
                &default
            }
        };
        let c_str = CString::new(tcti.as_str()).expect("TCTI parser rejects embedded NUL bytes");

        unsafe {
            let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = null_mut();
            let rc = Tss2_TctiLdr_Initialize(c_str.as_ptr(), &mut tcti_ctx);
            if rc != 0 {
                bail!("Tss2_TctiLdr_Initialize failed: 0x{rc:08x}");
            }

            let mut esys_ctx: *mut ESYS_CONTEXT = null_mut();
            let rc = Esys_Initialize(&mut esys_ctx, tcti_ctx, null_mut());
            if rc != 0 {
                Tss2_TctiLdr_Finalize(&mut tcti_ctx);
                bail!("Esys_Initialize failed: 0x{rc:08x}");
            }

            Ok(Self { ctx: esys_ctx })
        }
    }

    pub(crate) fn ptr(&mut self) -> *mut ESYS_CONTEXT {
        self.ctx
    }

    /// Set auth on an ESYS_TR handle.
    pub(crate) fn set_auth(&mut self, handle: ESYS_TR, auth_bytes: &[u8]) -> anyhow::Result<()> {
        unsafe {
            let mut tpm2b_auth = TPM2B_AUTH {
                size: auth_bytes.len() as u16,
                ..Default::default()
            };
            tpm2b_auth.buffer[..auth_bytes.len()].copy_from_slice(auth_bytes);
            let rc = Esys_TR_SetAuth(self.ctx, handle, &tpm2b_auth);
            if rc != 0 {
                bail!("Esys_TR_SetAuth failed: 0x{rc:08x}");
            }
        }
        Ok(())
    }
}

impl Drop for RawEsysContext {
    fn drop(&mut self) {
        unsafe {
            Esys_Finalize(&mut self.ctx);
        }
    }
}
