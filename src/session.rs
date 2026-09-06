// SPDX-License-Identifier: Apache-2.0

//! Session loading and management utilities.
//!
//! Functions in this module deal with TPM authorization sessions: loading
//! a previously saved session context from a file, starting EK policy
//! sessions, and running closures with a user-supplied or default session.

use std::path::Path;

use anyhow::Context;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{AuthHandle, ObjectHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::SavedTpmContext;
use tss_esapi::structures::SymmetricDefinition;

/// Load a session context from a JSON file and return it as an [`AuthSession`].
///
/// The file must contain a serialized [`SavedTpmContext`] (as produced by
/// [`tss_esapi::Context::context_save`]).  The `session_type` determines
/// whether the returned [`AuthSession`] is an HMAC session or a policy
/// session variant; the TPM itself tracks the real session type, but the
/// Rust wrapper needs to know in order to produce the right enum variant.
pub fn load_session_from_file(
    ctx: &mut tss_esapi::Context,
    path: &Path,
    session_type: SessionType,
) -> anyhow::Result<AuthSession> {
    let data =
        std::fs::read(path).with_context(|| format!("reading session file: {}", path.display()))?;
    let saved: SavedTpmContext =
        serde_json::from_slice(&data).context("failed to deserialize session context")?;
    let obj_handle: ObjectHandle = ctx
        .context_load(saved)
        .context("context_load (session) failed")?;
    let session_handle: SessionHandle = obj_handle.into();

    // AuthSession::create produces Some(_) for any non-None handle.
    AuthSession::create(session_type, session_handle, HashingAlgorithm::Sha256)
        .ok_or_else(|| anyhow::anyhow!("loaded session handle is not a valid auth session"))
}

/// Load an HMAC session when supplied, or select password authorization.
pub fn load_optional_auth_session(
    ctx: &mut tss_esapi::Context,
    path: Option<&Path>,
) -> anyhow::Result<AuthSession> {
    match path {
        Some(path) => load_session_from_file(ctx, path, SessionType::Hmac),
        None => Ok(AuthSession::Password),
    }
}

/// Load a policy or HMAC authorization session, or select password authorization.
pub fn load_optional_policy_or_hmac_session(
    ctx: &mut tss_esapi::Context,
    policy_path: Option<&Path>,
    hmac_path: Option<&Path>,
) -> anyhow::Result<AuthSession> {
    match (policy_path, hmac_path) {
        (Some(path), None) => load_session_from_file(ctx, path, SessionType::Policy),
        (None, Some(path)) => load_session_from_file(ctx, path, SessionType::Hmac),
        (None, None) => Ok(AuthSession::Password),
        (Some(_), Some(_)) => unreachable!("clap makes session arguments mutually exclusive"),
    }
}

/// Load an HMAC session for repeated command authorization when supplied.
pub fn load_command_session(
    ctx: &mut tss_esapi::Context,
    path: Option<&Path>,
) -> anyhow::Result<Option<AuthSession>> {
    path.map(|path| load_session_from_file(ctx, path, SessionType::Hmac))
        .transpose()
}

/// Execute a closure with a previously loaded session or a default null-auth session.
pub fn execute_with_command_session<F, T>(
    ctx: &mut tss_esapi::Context,
    session: Option<AuthSession>,
    f: F,
) -> anyhow::Result<T>
where
    F: FnOnce(&mut tss_esapi::Context) -> tss_esapi::Result<T>,
{
    match session {
        Some(session) => ctx
            .execute_with_session(Some(session), f)
            .map_err(|e| anyhow::anyhow!(e)),
        None => ctx
            .execute_with_nullauth_session(f)
            .map_err(|e| anyhow::anyhow!(e)),
    }
}

/// Execute a closure with either a loaded session or a default null-auth session.
///
/// When `session_path` is `Some`, the session context is loaded, used as the
/// sole authorization session, and saved back for a later CLI invocation. When `None`, the standard
/// [`execute_with_nullauth_session`](tss_esapi::Context::execute_with_nullauth_session)
/// convenience method is used.
pub fn execute_with_optional_session<F, T>(
    ctx: &mut tss_esapi::Context,
    session_path: Option<&Path>,
    f: F,
) -> anyhow::Result<T>
where
    F: FnOnce(&mut tss_esapi::Context) -> tss_esapi::Result<T>,
{
    execute_with_optional_session_type(ctx, session_path, SessionType::Hmac, f)
}

/// Execute a closure with a policy or HMAC session, or with null authorization when omitted.
pub fn execute_with_optional_policy_or_hmac_session<F, T>(
    ctx: &mut tss_esapi::Context,
    policy_path: Option<&Path>,
    hmac_path: Option<&Path>,
    f: F,
) -> anyhow::Result<T>
where
    F: FnOnce(&mut tss_esapi::Context) -> tss_esapi::Result<T>,
{
    match (policy_path, hmac_path) {
        (Some(path), None) => {
            execute_with_optional_session_type(ctx, Some(path), SessionType::Policy, f)
        }
        (None, Some(path)) => {
            execute_with_optional_session_type(ctx, Some(path), SessionType::Hmac, f)
        }
        (None, None) => execute_with_optional_session_type(ctx, None, SessionType::Hmac, f),
        (Some(_), Some(_)) => unreachable!("clap makes session arguments mutually exclusive"),
    }
}

/// Execute a closure with a policy session.
pub fn execute_with_policy_session<F, T>(
    ctx: &mut tss_esapi::Context,
    session_path: &Path,
    f: F,
) -> anyhow::Result<T>
where
    F: FnOnce(&mut tss_esapi::Context) -> tss_esapi::Result<T>,
{
    execute_with_optional_session_type(ctx, Some(session_path), SessionType::Policy, f)
}

fn execute_with_optional_session_type<F, T>(
    ctx: &mut tss_esapi::Context,
    session_path: Option<&Path>,
    session_type: SessionType,
    f: F,
) -> anyhow::Result<T>
where
    F: FnOnce(&mut tss_esapi::Context) -> tss_esapi::Result<T>,
{
    let Some(path) = session_path else {
        return execute_with_command_session(ctx, None, f);
    };

    let session = load_session_from_file(ctx, path, session_type)?;
    let session_handle = SessionHandle::from(session);
    let result = execute_with_command_session(ctx, Some(session), f);
    ctx.clear_sessions();

    if result.is_ok() {
        save_session_handle_to_file(ctx, session_handle, path)?;
    }

    result
}

/// Save a loaded authorization session for a later CLI invocation.
pub fn save_session_to_file(
    ctx: &mut tss_esapi::Context,
    session: AuthSession,
    path: &Path,
) -> anyhow::Result<()> {
    save_session_handle_to_file(ctx, SessionHandle::from(session), path)
}

fn save_session_handle_to_file(
    ctx: &mut tss_esapi::Context,
    session_handle: SessionHandle,
    path: &Path,
) -> anyhow::Result<()> {
    let saved = ctx
        .context_save(session_handle.into())
        .context("context_save (session) failed")?;
    let json = serde_json::to_string(&saved)?;
    std::fs::write(path, json).with_context(|| format!("saving session to {}", path.display()))?;
    Ok(())
}

/// Start a policy session and satisfy `PolicySecret(TPM_RH_ENDORSEMENT)`.
///
/// This is required for any command that uses the EK as a parent, since the
/// TCG default EK template has `adminWithPolicy`.
pub fn start_ek_policy_session(ctx: &mut tss_esapi::Context) -> anyhow::Result<PolicySession> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("TPM2_StartAuthSession failed")?
        .ok_or_else(|| anyhow::anyhow!("no session returned"))?;

    let policy_session: PolicySession = session
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected policy session"))?;

    // Satisfy the EK's policy: PolicySecret(endorsement hierarchy).
    ctx.set_sessions((Some(AuthSession::Password), None, None));
    ctx.policy_secret(
        policy_session,
        AuthHandle::Endorsement,
        Default::default(), // nonce_tpm
        Default::default(), // cp_hash_a
        Default::default(), // policy_ref
        None,               // expiration
    )
    .context("TPM2_PolicySecret failed")?;
    ctx.clear_sessions();

    Ok(policy_session)
}

/// Save a session handle to a JSON file and leak the context.
///
/// After `context_save` the C ESAPI layer invalidates the ESYS_TR, but the
/// Rust `handle_manager` retains a stale entry.  Consuming `ctx` by value
/// and calling `mem::forget` avoids spurious flush errors in `Context::drop`.
pub fn save_session_and_forget(
    mut ctx: tss_esapi::Context,
    handle: impl Into<ObjectHandle>,
    path: &Path,
) -> anyhow::Result<()> {
    let saved = ctx
        .context_save(handle.into())
        .context("context_save (session) failed")?;
    let json = serde_json::to_string(&saved)?;
    std::fs::write(path, json).with_context(|| format!("saving session to {}", path.display()))?;
    std::mem::forget(ctx);
    Ok(())
}

/// Flush a policy session handle.
pub fn flush_policy_session(
    ctx: &mut tss_esapi::Context,
    policy_session: PolicySession,
) -> anyhow::Result<()> {
    let ps_handle: ObjectHandle = SessionHandle::from(policy_session).into();
    ctx.flush_context(ps_handle)
        .context("failed to flush policy session")
}
