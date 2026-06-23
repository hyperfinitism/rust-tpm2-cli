// SPDX-License-Identifier: Apache-2.0

//! TPM handle/object loading utilities.
//!
//! Every function here requires a [`tss_esapi::Context`] to resolve a CLI
//! string (hex handle or file path) into a live TPM handle.  Pure argument
//! parsers that do **not** need a context live in [`crate::parse`].

use std::path::{Path, PathBuf};

use anyhow::Context;
use tss_esapi::handles::{KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, TpmHandle};
use tss_esapi::interface_types::reserved_handles::NvAuth;
use tss_esapi::structures::{Auth, SavedTpmContext};

use crate::parse::NvAuthEntity;

/// A resolved context source — either a file path or a raw hex handle.
///
/// Using this enum instead of a bare `String` prevents the ambiguity where a
/// value like `deadbeef` could be interpreted as either a hex handle or a
/// filename.  The CLI layer decides which variant applies at parse time.
#[derive(Debug, Clone)]
pub enum ContextSource {
    /// A JSON context file path (from `file:<path>` syntax).
    File(PathBuf),
    /// A raw persistent TPM handle (from `hex:<handle>` syntax).
    Handle(TpmHandle),
}

/// Load a [`KeyHandle`] from a [`ContextSource`].
pub fn load_key_from_source(
    ctx: &mut tss_esapi::Context,
    src: &ContextSource,
) -> anyhow::Result<KeyHandle> {
    match src {
        ContextSource::Handle(tpm_handle) => {
            let raw = u32::from(*tpm_handle);
            let obj = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(*tpm_handle))
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
        ContextSource::Handle(tpm_handle) => {
            let raw = u32::from(*tpm_handle);
            let obj = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(*tpm_handle))
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
    let saved: SavedTpmContext =
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
    let saved: SavedTpmContext =
        serde_json::from_slice(&data).context("failed to deserialize context")?;
    let handle = ctx.context_load(saved).context("context_load failed")?;
    Ok(handle)
}

/// Load an NV index from its TPM handle.
pub fn load_nv_index(
    ctx: &mut tss_esapi::Context,
    nv_tpm_handle: NvIndexTpmHandle,
) -> anyhow::Result<NvIndexHandle> {
    let raw = u32::from(nv_tpm_handle);
    let tpm_handle: TpmHandle = nv_tpm_handle.into();
    let object_handle = ctx
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
        .with_context(|| format!("failed to load NV index 0x{raw:08x}"))?;
    Ok(object_handle.into())
}

/// Convert the CLI NV authorization selector to the corresponding ESAPI type.
pub fn nv_auth_from_entity(entity: NvAuthEntity, nv_handle: NvIndexHandle) -> NvAuth {
    match entity {
        NvAuthEntity::Owner => NvAuth::Owner,
        NvAuthEntity::Platform => NvAuth::Platform,
        NvAuthEntity::NvIndex => NvAuth::NvIndex(nv_handle),
    }
}

/// Set the password associated with an NV authorization entity.
pub fn set_nv_auth(
    ctx: &mut tss_esapi::Context,
    nv_auth: NvAuth,
    auth: Auth,
) -> anyhow::Result<()> {
    let auth_handle = tss_esapi::handles::AuthHandle::from(nv_auth);
    ctx.tr_set_auth(auth_handle.into(), auth)
        .context("failed to set NV authorization")
}

/// Resolve the NV authorization entity for `nvread` / `nvwrite`.
///
/// The selector has already been parsed and validated by clap.
pub fn resolve_nv_auth(
    ctx: &mut tss_esapi::Context,
    entity: NvAuthEntity,
    nv_handle: NvIndexTpmHandle,
) -> anyhow::Result<NvAuth> {
    match entity {
        NvAuthEntity::Owner => Ok(NvAuth::Owner),
        NvAuthEntity::Platform => Ok(NvAuth::Platform),
        NvAuthEntity::NvIndex => {
            let tpm_handle: TpmHandle = nv_handle.into();
            let obj = ctx
                .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))
                .context("failed to load NV index for auth")?;
            Ok(NvAuth::NvIndex(obj.into()))
        }
    }
}
