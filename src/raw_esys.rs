// SPDX-License-Identifier: Apache-2.0

//! Raw ESYS FFI wrappers for TPM2 commands not yet in tss-esapi.
//!
//! tss-esapi 7.6.0 does not wrap `TPM2_Commit` or `TPM2_EC_Ephemeral`.
//! This module calls the C ESAPI functions directly through tss-esapi-sys,
//! managing its own raw `ESYS_CONTEXT`.

use std::ffi::CString;
use std::path::Path;
use std::ptr::{null, null_mut};

use anyhow::{Context, bail};
use tss_esapi::tss2_esys::*;

use crate::tcti::resolve_tcti_str;

// -----------------------------------------------------------------------
// Raw context helpers
// -----------------------------------------------------------------------

/// A thin RAII wrapper around a raw `ESYS_CONTEXT*`.
pub(crate) struct RawEsysContext {
    ctx: *mut ESYS_CONTEXT,
}

impl RawEsysContext {
    /// Create a new raw ESYS context from a TCTI config string.
    pub(crate) fn new(tcti: Option<&str>) -> anyhow::Result<Self> {
        let tcti_str = resolve_tcti_str(tcti);
        let c_str = CString::new(tcti_str.as_str()).context("TCTI string contains NUL")?;

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

    /// Resolve an [`NvAuthEntity`] to an `ESYS_TR` handle, using `nv_handle`
    /// when the entity is [`NvAuthEntity::NvIndex`].
    pub(crate) fn resolve_nv_auth_entity(
        entity: crate::parse::NvAuthEntity,
        nv_handle: ESYS_TR,
    ) -> ESYS_TR {
        use crate::parse::NvAuthEntity;
        match entity {
            NvAuthEntity::Owner => ESYS_TR_RH_OWNER,
            NvAuthEntity::Platform => ESYS_TR_RH_PLATFORM,
            NvAuthEntity::NvIndex => nv_handle,
        }
    }

    /// Resolve a persistent TPM handle to an ESYS_TR.
    pub(crate) fn tr_from_tpm_public(&mut self, tpm_handle: u32) -> anyhow::Result<ESYS_TR> {
        unsafe {
            let mut esys_handle: ESYS_TR = ESYS_TR_NONE;
            let rc = Esys_TR_FromTPMPublic(
                self.ctx,
                tpm_handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &mut esys_handle,
            );
            if rc != 0 {
                bail!("Esys_TR_FromTPMPublic failed: 0x{rc:08x}");
            }
            Ok(esys_handle)
        }
    }

    /// Load a saved context (from JSON file) and return the ESYS_TR.
    pub(crate) fn context_load(&mut self, path: &str) -> anyhow::Result<ESYS_TR> {
        let data = std::fs::read(path).with_context(|| format!("reading context file: {path}"))?;
        let saved: tss_esapi::structures::SavedTpmContext =
            serde_json::from_slice(&data).context("failed to deserialize context")?;
        let tpms: TPMS_CONTEXT = saved.into();

        unsafe {
            let mut handle: ESYS_TR = ESYS_TR_NONE;
            let rc = Esys_ContextLoad(self.ctx, &tpms, &mut handle);
            if rc != 0 {
                bail!("Esys_ContextLoad failed: 0x{rc:08x}");
            }
            Ok(handle)
        }
    }

    /// Resolve a [`ContextSource`] to an ESYS_TR.
    pub(crate) fn resolve_handle_from_source(
        &mut self,
        src: &crate::handle::ContextSource,
    ) -> anyhow::Result<ESYS_TR> {
        match src {
            crate::handle::ContextSource::Handle(raw) => self.tr_from_tpm_public(*raw),
            crate::handle::ContextSource::File(path) => {
                self.context_load(path.to_str().unwrap_or_default())
            }
        }
    }

    /// Parse a hex NV index string and resolve it to an ESYS_TR.
    pub(crate) fn resolve_nv_index(&mut self, s: &str) -> anyhow::Result<ESYS_TR> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let raw: u32 = u32::from_str_radix(stripped, 16)
            .map_err(|_| anyhow::anyhow!("invalid NV index: {s}"))?;
        self.tr_from_tpm_public(raw)
    }

    /// Save a session/object handle to a JSON context file via Esys_ContextSave.
    pub(crate) fn context_save_to_file(
        &mut self,
        handle: ESYS_TR,
        path: &Path,
    ) -> anyhow::Result<()> {
        unsafe {
            let mut saved_ptr: *mut TPMS_CONTEXT = null_mut();
            let rc = Esys_ContextSave(self.ctx, handle, &mut saved_ptr);
            if rc != 0 {
                bail!("Esys_ContextSave failed: 0x{rc:08x}");
            }
            let saved = *saved_ptr;
            Esys_Free(saved_ptr as *mut _);
            let tpms: tss_esapi::structures::SavedTpmContext = saved
                .try_into()
                .map_err(|e| anyhow::anyhow!("SavedTpmContext conversion failed: {e:?}"))?;
            let json = serde_json::to_string(&tpms)?;
            std::fs::write(path, json)
                .with_context(|| format!("writing context to {}", path.display()))?;
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

// -----------------------------------------------------------------------
// TPM2_Commit
// -----------------------------------------------------------------------

/// Result of a TPM2_Commit operation.
pub struct CommitResult {
    pub k: Vec<u8>,
    pub l: Vec<u8>,
    pub e: Vec<u8>,
    pub counter: u16,
}

/// Execute TPM2_Commit via raw ESYS FFI.
pub fn commit(
    tcti: Option<&str>,
    key_context: &crate::handle::ContextSource,
    auth: Option<&str>,
    p1: Option<&[u8]>,
    s2: Option<&[u8]>,
    y2: Option<&[u8]>,
) -> anyhow::Result<CommitResult> {
    let mut raw = RawEsysContext::new(tcti)?;
    let sign_handle = raw.resolve_handle_from_source(key_context)?;

    // Set auth on the key if provided.
    if let Some(auth_str) = auth {
        let auth_val = crate::parse::parse_auth(auth_str)?;
        unsafe {
            let mut tpm2b_auth = TPM2B_AUTH {
                size: auth_val.as_bytes().len() as u16,
                ..Default::default()
            };
            tpm2b_auth.buffer[..auth_val.as_bytes().len()].copy_from_slice(auth_val.as_bytes());
            let rc = Esys_TR_SetAuth(raw.ptr(), sign_handle, &tpm2b_auth);
            if rc != 0 {
                bail!("Esys_TR_SetAuth failed: 0x{rc:08x}");
            }
        }
    }

    // Build input structures.
    let p1_struct = p1.map(bytes_to_ecc_point);
    let s2_struct = s2.map(|data| {
        let mut sd = TPM2B_SENSITIVE_DATA::default();
        let len = data.len().min(sd.buffer.len());
        sd.size = len as u16;
        sd.buffer[..len].copy_from_slice(&data[..len]);
        sd
    });
    let y2_struct = y2.map(|data| {
        let mut ep = TPM2B_ECC_PARAMETER::default();
        let len = data.len().min(ep.buffer.len());
        ep.size = len as u16;
        ep.buffer[..len].copy_from_slice(&data[..len]);
        ep
    });

    let p1_ptr = p1_struct.as_ref().map_or(null(), |p| p as *const _);
    let s2_ptr = s2_struct.as_ref().map_or(null(), |p| p as *const _);
    let y2_ptr = y2_struct.as_ref().map_or(null(), |p| p as *const _);

    unsafe {
        let mut k_ptr: *mut TPM2B_ECC_POINT = null_mut();
        let mut l_ptr: *mut TPM2B_ECC_POINT = null_mut();
        let mut e_ptr: *mut TPM2B_ECC_POINT = null_mut();
        let mut counter: u16 = 0;

        let rc = Esys_Commit(
            raw.ptr(),
            sign_handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            p1_ptr,
            s2_ptr,
            y2_ptr,
            &mut k_ptr,
            &mut l_ptr,
            &mut e_ptr,
            &mut counter,
        );
        if rc != 0 {
            bail!("Esys_Commit failed: 0x{rc:08x}");
        }

        let k = ecc_point_ptr_to_bytes(k_ptr);
        let l = ecc_point_ptr_to_bytes(l_ptr);
        let e = ecc_point_ptr_to_bytes(e_ptr);

        Esys_Free(k_ptr as *mut _);
        Esys_Free(l_ptr as *mut _);
        Esys_Free(e_ptr as *mut _);

        Ok(CommitResult { k, l, e, counter })
    }
}

// -----------------------------------------------------------------------
// TPM2_EC_Ephemeral
// -----------------------------------------------------------------------

/// Execute TPM2_EC_Ephemeral via raw ESYS FFI.
///
/// Returns `(q_point_bytes, counter)`.
pub fn ec_ephemeral(tcti: Option<&str>, curve_id: u16) -> anyhow::Result<(Vec<u8>, u16)> {
    let mut raw = RawEsysContext::new(tcti)?;

    unsafe {
        let mut q_ptr: *mut TPM2B_ECC_POINT = null_mut();
        let mut counter: u16 = 0;

        let rc = Esys_EC_Ephemeral(
            raw.ptr(),
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            curve_id,
            &mut q_ptr,
            &mut counter,
        );
        if rc != 0 {
            bail!("Esys_EC_Ephemeral failed: 0x{rc:08x}");
        }

        let q = ecc_point_ptr_to_bytes(q_ptr);
        Esys_Free(q_ptr as *mut _);

        Ok((q, counter))
    }
}

// -----------------------------------------------------------------------
// Attestation / signature output helpers
// -----------------------------------------------------------------------

/// Write a raw `TPM2B_ATTEST` to a file (attestation data only, no header).
///
/// # Safety
/// `info` must be a valid pointer returned by an ESYS function, or null.
pub(crate) unsafe fn write_raw_attestation(
    info: *const TPM2B_ATTEST,
    path: &Path,
) -> anyhow::Result<()> {
    if info.is_null() {
        bail!("attestation pointer is null");
    }
    let attest = unsafe { &*info };
    let data = &attest.attestationData[..attest.size as usize];
    crate::output::write_to_file(path, data)
        .with_context(|| format!("writing attestation to {}", path.display()))
}

/// Write a raw `TPMT_SIGNATURE` to a file as its full struct bytes.
///
/// # Safety
/// `sig` must be a valid pointer returned by an ESYS function, or null.
pub(crate) unsafe fn write_raw_signature(
    sig: *const TPMT_SIGNATURE,
    path: &Path,
) -> anyhow::Result<()> {
    if sig.is_null() {
        bail!("signature pointer is null");
    }
    let sig_bytes = unsafe {
        std::slice::from_raw_parts(sig as *const u8, std::mem::size_of::<TPMT_SIGNATURE>())
    };
    crate::output::write_to_file(path, sig_bytes)
        .with_context(|| format!("writing signature to {}", path.display()))
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn bytes_to_ecc_point(data: &[u8]) -> TPM2B_ECC_POINT {
    let mut point = TPM2B_ECC_POINT::default();
    // Split data in half: first half is x, second half is y.
    let half = data.len() / 2;
    let x = &data[..half];
    let y = &data[half..];
    point.point.x.size = x.len() as u16;
    point.point.x.buffer[..x.len()].copy_from_slice(x);
    point.point.y.size = y.len() as u16;
    point.point.y.buffer[..y.len()].copy_from_slice(y);
    point.size = std::mem::size_of::<TPMS_ECC_POINT>() as u16;
    point
}

unsafe fn ecc_point_ptr_to_bytes(ptr: *mut TPM2B_ECC_POINT) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    let p = unsafe { &*ptr };
    let x_len = p.point.x.size as usize;
    let y_len = p.point.y.size as usize;
    let mut out = Vec::with_capacity(x_len + y_len);
    out.extend_from_slice(&p.point.x.buffer[..x_len]);
    out.extend_from_slice(&p.point.y.buffer[..y_len]);
    out
}
