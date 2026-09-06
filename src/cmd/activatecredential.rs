// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::reserved_handles::HierarchyAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{Auth, EncryptedSecret, IdObject};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::{
    flush_policy_session, load_optional_policy_or_hmac_session, load_session_from_file,
    save_session_to_file, start_ek_policy_session,
};
#[derive(Parser)]
pub struct ActivateCredentialCmd {
    /// Credentialed key context — the object the credential is bound to (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "credentialedkey-context", value_parser = parse_context_source)]
    pub credentialed_context: ContextSource,

    /// Credential key context — the key used to decrypt the seed (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "credentialkey-context", value_parser = parse_context_source)]
    pub credential_key_context: ContextSource,

    /// Authorization value for the credentialed key
    #[arg(short = 'p', long = "credentialedkey-auth", value_parser = parse::parse_auth)]
    pub credentialed_auth: Option<Auth>,

    /// Authorization value for the credential key (EK).
    ///
    /// Use `session:<path>` to supply an already-satisfied policy session,
    /// or a plain password / `hex:` / `file:` value for the endorsement
    /// hierarchy auth used when starting an internal EK policy session.
    #[arg(short = 'P', long = "credentialkey-auth", value_parser = parse::parse_credential_key_auth)]
    pub credential_key_auth: Option<parse::CredentialKeyAuth>,

    /// Input credential blob file (from tpm2 makecredential)
    #[arg(short = 'i', long = "credential-blob")]
    pub credential_blob: PathBuf,

    /// Output file for the decrypted credential secret
    #[arg(short = 'o', long = "certinfo-data")]
    pub certinfo_data: PathBuf,

    /// HMAC session context file for credentialed key authorization
    #[arg(short = 'S', long = "session", conflicts_with = "policy_session")]
    pub session: Option<PathBuf>,

    /// Policy session context file for credentialed key authorization
    #[arg(long = "policy-session", conflicts_with = "session")]
    pub policy_session: Option<PathBuf>,
}

impl ActivateCredentialCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let activate_handle = load_key_from_source(&mut ctx, &self.credentialed_context)?;
        let key_handle = load_key_from_source(&mut ctx, &self.credential_key_context)?;
        if let Some(ref auth) = self.credentialed_auth {
            ctx.tr_set_auth(activate_handle.into(), auth.clone())
                .context("failed to set credentialed key auth")?;
        }
        let blob = std::fs::read(&self.credential_blob).with_context(|| {
            format!(
                "reading credential blob: {}",
                self.credential_blob.display()
            )
        })?;
        let (id_object, encrypted_secret) = parse_credential_blob(&blob)?;
        let (ek_session, external_session_path) = match &self.credential_key_auth {
            Some(parse::CredentialKeyAuth::Session(path)) => (
                load_session_from_file(&mut ctx, path, SessionType::Policy)?,
                Some(path.as_path()),
            ),
            auth => {
                if let Some(parse::CredentialKeyAuth::Auth(auth)) = auth {
                    let eh_obj: ObjectHandle = HierarchyAuth::Endorsement.into();
                    ctx.tr_set_auth(eh_obj, auth.clone())
                        .context("failed to set endorsement hierarchy auth")?;
                }
                let ps = start_ek_policy_session(&mut ctx)?;
                (AuthSession::PolicySession(ps), None)
            }
        };
        let activate_session = load_optional_policy_or_hmac_session(
            &mut ctx,
            self.policy_session.as_deref(),
            self.session.as_deref(),
        )?;
        ctx.set_sessions((Some(activate_session), Some(ek_session), None));
        let result = ctx
            .activate_credential(activate_handle, key_handle, id_object, encrypted_secret)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let cert_info = result.context("TPM2_ActivateCredential failed")?;

        if let Some(path) = self.policy_session.as_deref().or(self.session.as_deref()) {
            save_session_to_file(&mut ctx, activate_session, path)?;
        }
        if let Some(path) = external_session_path {
            save_session_to_file(&mut ctx, ek_session, path)?;
        } else if let AuthSession::PolicySession(ps) = ek_session {
            flush_policy_session(&mut ctx, ps)?;
        }

        std::fs::write(&self.certinfo_data, cert_info.as_bytes())
            .with_context(|| format!("writing certinfo to {}", self.certinfo_data.display()))?;
        info!("certinfo saved to {}", self.certinfo_data.display());

        Ok(())
    }
}

/// Parse a credential blob file into `(IdObject, EncryptedSecret)`.
///
/// Format: `[u16 BE id_len][id_data][u16 BE secret_len][secret_data]`.
fn parse_credential_blob(blob: &[u8]) -> anyhow::Result<(IdObject, EncryptedSecret)> {
    if blob.len() < 4 {
        anyhow::bail!("credential blob too short");
    }
    let id_size = u16::from_be_bytes([blob[0], blob[1]]) as usize;
    let id_end = 2 + id_size;
    if blob.len() < id_end + 2 {
        anyhow::bail!("credential blob truncated");
    }
    let id_object = IdObject::try_from(blob[2..id_end].to_vec())
        .map_err(|e| anyhow::anyhow!("invalid IdObject: {e}"))?;

    let secret_start = id_end;
    let secret_size = u16::from_be_bytes([blob[secret_start], blob[secret_start + 1]]) as usize;
    let secret_end = secret_start + 2 + secret_size;
    if blob.len() < secret_end {
        anyhow::bail!("credential blob truncated (encrypted secret)");
    }
    let encrypted_secret = EncryptedSecret::try_from(blob[secret_start + 2..secret_end].to_vec())
        .map_err(|e| anyhow::anyhow!("invalid EncryptedSecret: {e}"))?;

    Ok((id_object, encrypted_secret))
}
