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
use tss_esapi::structures::SymmetricDefinition;
use tss_esapi::utils::TpmsContext;

/// Load a session context from a JSON file and return it as an [`AuthSession`].
///
/// The file must contain a serialized [`TpmsContext`] (as produced by
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
    let saved: TpmsContext =
        serde_json::from_slice(&data).context("failed to deserialize session context")?;
    let obj_handle: ObjectHandle = ctx
        .context_load(saved)
        .context("context_load (session) failed")?;
    let session_handle: SessionHandle = obj_handle.into();

    // AuthSession::create produces Some(_) for any non-None handle.
    AuthSession::create(session_type, session_handle, HashingAlgorithm::Sha256)
        .ok_or_else(|| anyhow::anyhow!("loaded session handle is not a valid auth session"))
}

/// Execute a closure with either a loaded session or a default null-auth session.
///
/// When `session_path` is `Some`, the session context file is loaded and set
/// as the sole authorization session.  When `None`, the standard
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
    match session_path {
        Some(path) => {
            let session = load_session_from_file(ctx, path, SessionType::Hmac)?;
            ctx.set_sessions((Some(session), None, None));
            let result = f(ctx).map_err(|e| anyhow::anyhow!(e))?;
            ctx.clear_sessions();
            Ok(result)
        }
        None => ctx
            .execute_with_nullauth_session(f)
            .map_err(|e| anyhow::anyhow!(e)),
    }
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
