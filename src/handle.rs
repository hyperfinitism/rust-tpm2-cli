// SPDX-License-Identifier: Apache-2.0

//! TPM handle/object loading utilities.
//!
//! Every function here requires a [`tss_esapi::Context`] to resolve a CLI
//! string (hex handle or file path) into a live TPM handle.  Pure argument
//! parsers that do **not** need a context live in [`crate::parse`].

use std::path::{Path, PathBuf};

use anyhow::Context;
use tss_esapi::handles::{KeyHandle, NvIndexTpmHandle, ObjectHandle, TpmHandle};
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::utils::TpmsContext;

// ---------------------------------------------------------------------------
// ContextSource — type-safe split of "hex handle vs. file path"
// ---------------------------------------------------------------------------

/// A resolved context source — either a file path or a raw hex handle.
///
/// Using this enum instead of a bare `String` prevents the ambiguity where a
/// value like `deadbeef` could be interpreted as either a hex handle or a
/// filename.  The CLI layer decides which variant applies at parse time.
#[derive(Debug, Clone)]
pub enum ContextSource {
    /// A JSON context file path (from `--context` / `-c`).
    File(PathBuf),
    /// A raw persistent TPM handle (from `--context-handle` / `-H`).
    Handle(u32),
}

/// Load a [`KeyHandle`] from a [`ContextSource`].
pub fn load_key_from_source(
    ctx: &mut tss_esapi::Context,
    src: &ContextSource,
) -> anyhow::Result<KeyHandle> {
    match src {
        ContextSource::Handle(raw) => {
            let tpm_handle = TpmHandle::try_from(*raw)
                .map_err(|e| anyhow::anyhow!("invalid TPM handle 0x{raw:08x}: {e}"))?;
            let obj = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
                .with_context(|| format!("failed to load handle 0x{raw:08x}"))?;
            Ok(obj.into())
        }
        ContextSource::File(path) => load_key_context_file(ctx, path),
    }
}

/// Load an [`ObjectHandle`] from a [`ContextSource`].
pub fn load_object_from_source(
    ctx: &mut tss_esapi::Context,
    src: &ContextSource,
) -> anyhow::Result<ObjectHandle> {
    match src {
        ContextSource::Handle(raw) => {
            let tpm_handle = TpmHandle::try_from(*raw)
                .map_err(|e| anyhow::anyhow!("invalid TPM handle 0x{raw:08x}: {e}"))?;
            let obj = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
                .with_context(|| format!("failed to load handle 0x{raw:08x}"))?;
            Ok(obj)
        }
        ContextSource::File(path) => load_object_context_file(ctx, path),
    }
}

/// Load a key handle from a JSON context file.
pub fn load_key_context_file(
    ctx: &mut tss_esapi::Context,
    path: &Path,
) -> anyhow::Result<KeyHandle> {
    let data =
        std::fs::read(path).with_context(|| format!("reading context file: {}", path.display()))?;
    let saved: TpmsContext =
        serde_json::from_slice(&data).context("failed to deserialize context")?;
    let handle = ctx.context_load(saved).context("context_load failed")?;
    Ok(handle.into())
}

/// Load a generic object handle from a JSON context file.
pub fn load_object_context_file(
    ctx: &mut tss_esapi::Context,
    path: &Path,
) -> anyhow::Result<ObjectHandle> {
    let data =
        std::fs::read(path).with_context(|| format!("reading context file: {}", path.display()))?;
    let saved: TpmsContext =
        serde_json::from_slice(&data).context("failed to deserialize context")?;
    let handle = ctx.context_load(saved).context("context_load failed")?;
    Ok(handle)
}

/// Resolve the NV authorization entity for `nvread` / `nvwrite`.
///
/// - `"o"` / `"owner"`    → [`NvAuth::Owner`]
/// - `"p"` / `"platform"` → [`NvAuth::Platform`]
/// - anything else        → load the NV index itself as the auth entity
pub fn resolve_nv_auth(
    ctx: &mut tss_esapi::Context,
    hierarchy: &str,
    nv_handle: NvIndexTpmHandle,
) -> anyhow::Result<NvAuth> {
    match hierarchy.to_lowercase().as_str() {
        "o" | "owner" => Ok(NvAuth::Owner),
        "p" | "platform" => Ok(NvAuth::Platform),
        _ => {
            let tpm_handle: TpmHandle = nv_handle.into();
            let obj = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
                .context("failed to load NV index for auth")?;
            Ok(NvAuth::NvIndex(obj.into()))
        }
    }
}
