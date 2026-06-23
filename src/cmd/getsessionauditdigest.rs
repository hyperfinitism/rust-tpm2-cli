// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{Auth, Data};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::load_session_from_file;

/// Get the session audit digest signed by a key.
///
/// Wraps TPM2_GetSessionAuditDigest (raw FFI).
#[derive(Parser)]
pub struct GetSessionAuditDigestCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "signing-key-context", value_parser = parse_context_source)]
    pub signing_key_context: ContextSource,

    /// Auth hierarchy for the privacy admin (e/endorsement)
    #[arg(short = 'C', long = "privacy-admin", default_value = "e", value_parser = parse::parse_esys_hierarchy)]
    pub privacy_admin: u32,

    /// Session context file to audit
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Auth for the signing key
    #[arg(short = 'P', long = "signing-key-auth", value_parser = parse::parse_auth)]
    pub signing_key_auth: Option<Auth>,

    /// Auth for the privacy admin hierarchy
    #[arg(short = 'p', long = "hierarchy-auth", value_parser = parse::parse_auth)]
    pub hierarchy_auth: Option<Auth>,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = crate::parse::parse_qualification)]
    pub qualification: Option<crate::parse::Qualification>,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(long = "signature")]
    pub signature: Option<PathBuf>,
}

impl GetSessionAuditDigestCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;
        let privacy_handle = object_handle_from_esys_hierarchy(self.privacy_admin)?;
        let sign_handle = load_key_from_source(&mut ctx, &self.signing_key_context)?;

        let audit_session = load_session_from_file(&mut ctx, &self.session, SessionType::Hmac)?;
        let session_handle = SessionHandle::from(audit_session);

        if let Some(ref auth) = self.hierarchy_auth {
            ctx.tr_set_auth(privacy_handle, auth.clone())
                .context("failed to set privacy hierarchy auth")?;
        }
        if let Some(ref auth) = self.signing_key_auth {
            ctx.tr_set_auth(sign_handle.into(), auth.clone())
                .context("failed to set signing key auth")?;
        }

        let qualifying_data = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };

        let scheme = parse::parse_signature_scheme("null", HashingAlgorithm::Sha256)
            .map_err(anyhow::Error::msg)?;

        ctx.set_sessions((
            Some(AuthSession::Password),
            Some(AuthSession::Password),
            None,
        ));
        let result = ctx
            .get_session_audit_digest(
                privacy_handle,
                sign_handle,
                session_handle,
                qualifying_data,
                scheme,
            )
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (attest, signature) = result.context("TPM2_GetSessionAuditDigest failed")?;

        if let Some(ref path) = self.attestation {
            let bytes = attest.marshall().context("failed to marshal TPMS_ATTEST")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing attestation to {}", path.display()))?;
            info!("session audit attestation saved to {}", path.display());
        }

        if let Some(ref path) = self.signature {
            let bytes = signature
                .marshall()
                .context("failed to marshal TPMT_SIGNATURE")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing signature to {}", path.display()))?;
            info!("signature saved to {}", path.display());
        }

        info!("session audit digest retrieved");
        Ok(())
    }
}

fn object_handle_from_esys_hierarchy(handle: u32) -> anyhow::Result<ObjectHandle> {
    use tss_esapi::tss2_esys::{
        ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_NULL, ESYS_TR_RH_OWNER,
        ESYS_TR_RH_PLATFORM,
    };

    match handle {
        ESYS_TR_RH_OWNER => Ok(ObjectHandle::Owner),
        ESYS_TR_RH_PLATFORM => Ok(ObjectHandle::Platform),
        ESYS_TR_RH_ENDORSEMENT => Ok(ObjectHandle::Endorsement),
        ESYS_TR_RH_NULL => Ok(ObjectHandle::Null),
        ESYS_TR_RH_LOCKOUT => Ok(ObjectHandle::Lockout),
        _ => anyhow::bail!("unsupported privacy admin hierarchy: 0x{handle:08x}"),
    }
}
