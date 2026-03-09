use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::resource_handles::HierarchyAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{EncryptedSecret, IdObject};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse;
use crate::parse::parse_hex_u32;
use crate::session::{flush_policy_session, load_session_from_file, start_ek_policy_session};

/// Activate a credential associated with a TPM object.
///
/// Wraps `TPM2_ActivateCredential`: given a credential blob produced by
/// `tpm2 makecredential`, decrypts it using the credential key (typically
/// an EK) and verifies the binding to the credentialed key (typically an AK).
#[derive(Parser)]
pub struct ActivateCredentialCmd {
    /// Credentialed key context file — the object the credential is bound to (AK)
    #[arg(
        short = 'c',
        long = "credentialedkey-context",
        conflicts_with = "credentialed_context_handle"
    )]
    pub credentialed_context: Option<PathBuf>,

    /// Credentialed key handle (hex, e.g. 0x81000001)
    #[arg(long = "credentialedkey-context-handle", value_parser = parse_hex_u32, conflicts_with = "credentialed_context")]
    pub credentialed_context_handle: Option<u32>,

    /// Credential key context file — the key used to decrypt the seed (EK)
    #[arg(
        short = 'C',
        long = "credentialkey-context",
        conflicts_with = "credential_key_context_handle"
    )]
    pub credential_key_context: Option<PathBuf>,

    /// Credential key handle (hex, e.g. 0x81000001)
    #[arg(long = "credentialkey-context-handle", value_parser = parse_hex_u32, conflicts_with = "credential_key_context")]
    pub credential_key_context_handle: Option<u32>,

    /// Auth value for the credentialed key
    #[arg(short = 'p', long = "credentialedkey-auth")]
    pub credentialed_auth: Option<String>,

    /// Auth for the credential key (EK).
    ///
    /// Use `session:<path>` to supply an already-satisfied policy session,
    /// or a plain password / `hex:` / `file:` value for the endorsement
    /// hierarchy auth used when starting an internal EK policy session.
    #[arg(short = 'P', long = "credentialkey-auth")]
    pub credential_key_auth: Option<String>,

    /// Input credential blob file (from tpm2 makecredential)
    #[arg(short = 'i', long = "credential-blob")]
    pub credential_blob: PathBuf,

    /// Output file for the decrypted credential secret
    #[arg(short = 'o', long = "certinfo-data")]
    pub certinfo_data: PathBuf,
}

impl ActivateCredentialCmd {
    fn credentialed_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.credentialed_context, self.credentialed_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --credentialedkey-context or --credentialedkey-context-handle must be provided"
            ),
        }
    }

    fn credential_key_context_source(&self) -> anyhow::Result<ContextSource> {
        match (
            &self.credential_key_context,
            self.credential_key_context_handle,
        ) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --credentialkey-context or --credentialkey-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let activate_handle = load_key_from_source(&mut ctx, &self.credentialed_context_source()?)?;
        let key_handle = load_key_from_source(&mut ctx, &self.credential_key_context_source()?)?;

        // Set auth on the credentialed key (AK) if provided.
        if let Some(ref a) = self.credentialed_auth {
            let auth = parse::parse_auth(a)?;
            ctx.tr_set_auth(activate_handle.into(), auth)
                .context("failed to set credentialed key auth")?;
        }

        // Read and parse the credential blob.
        let blob = std::fs::read(&self.credential_blob).with_context(|| {
            format!(
                "reading credential blob: {}",
                self.credential_blob.display()
            )
        })?;
        let (id_object, encrypted_secret) = parse_credential_blob(&blob)?;

        // Determine the EK authorization session.
        //
        // If `-P session:<path>` is given, load the external (already
        // satisfied) policy session from the file.  Otherwise start an
        // internal EK policy session with PolicySecret(endorsement).
        let external_session = self.is_external_session();
        let ek_session = if let Some(path) = external_session {
            load_session_from_file(&mut ctx, path.as_ref(), SessionType::Policy)?
        } else {
            // Set endorsement hierarchy auth if a password was given.
            if let Some(ref a) = self.credential_key_auth {
                let auth = parse::parse_auth(a)?;
                let eh_obj: ObjectHandle = HierarchyAuth::Endorsement.into();
                ctx.tr_set_auth(eh_obj, auth)
                    .context("failed to set endorsement hierarchy auth")?;
            }
            let ps = start_ek_policy_session(&mut ctx)?;
            AuthSession::PolicySession(ps)
        };

        // ActivateCredential needs two auth sessions:
        //   session 1 → credentialed key (AK): password
        //   session 2 → credential key (EK): policy
        ctx.set_sessions((Some(AuthSession::Password), Some(ek_session), None));
        let cert_info = ctx
            .activate_credential(activate_handle, key_handle, id_object, encrypted_secret)
            .context("TPM2_ActivateCredential failed")?;
        ctx.clear_sessions();

        if external_session.is_none() {
            // Flush the internally-created policy session.
            if let AuthSession::PolicySession(ps) = ek_session {
                flush_policy_session(&mut ctx, ps)?;
            }
        }

        // Write decrypted secret.
        std::fs::write(&self.certinfo_data, cert_info.value())
            .with_context(|| format!("writing certinfo to {}", self.certinfo_data.display()))?;
        info!("certinfo saved to {}", self.certinfo_data.display());

        Ok(())
    }

    /// If `-P` starts with `session:`, return the file path portion.
    fn is_external_session(&self) -> Option<&str> {
        self.credential_key_auth
            .as_deref()
            .and_then(|v| v.strip_prefix("session:"))
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
