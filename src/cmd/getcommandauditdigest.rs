// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Data};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::load_optional_auth_session;
#[derive(Parser)]
pub struct GetCommandAuditDigestCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "signing-key-context", value_parser = parse_context_source)]
    pub signing_key_context: ContextSource,

    /// Privacy administrator hierarchy (endorsement or platform)
    #[arg(short = 'C', long = "privacy-admin", default_value = "e", value_parser = parse::parse_endorsement_or_platform_auth_handle)]
    pub privacy_admin: AuthHandle,

    /// Authorization value for the signing key
    #[arg(short = 'P', long = "signing-key-auth", value_parser = parse::parse_auth)]
    pub signing_key_auth: Option<Auth>,

    /// Authorization value for the privacy administrator hierarchy
    #[arg(short = 'p', long = "hierarchy-auth", value_parser = parse::parse_auth)]
    pub hierarchy_auth: Option<Auth>,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = crate::parse::parse_qualification)]
    pub qualification: Option<crate::parse::Qualification>,

    /// Hash algorithm used by the signature scheme
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null", value_parser = parse::parse_signature_scheme_kind)]
    pub scheme: parse::SignatureSchemeKind,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(long = "signature")]
    pub signature: Option<PathBuf>,

    /// Session context file for privacy administrator authorization
    #[arg(long = "privacy-session")]
    pub privacy_session: Option<PathBuf>,

    /// Session context file for signing key authorization
    #[arg(long = "signing-session")]
    pub signing_session: Option<PathBuf>,
}

impl GetCommandAuditDigestCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let privacy_handle = self.privacy_admin.into();
        let sign_handle = load_key_from_source(&mut ctx, &self.signing_key_context)?;

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

        let scheme = self.scheme.with_hash(self.hash_algorithm);

        let privacy_session =
            load_optional_auth_session(&mut ctx, self.privacy_session.as_deref())?;
        let signing_session =
            load_optional_auth_session(&mut ctx, self.signing_session.as_deref())?;
        ctx.set_sessions((Some(privacy_session), Some(signing_session), None));
        let result = ctx
            .get_command_audit_digest(privacy_handle, sign_handle, qualifying_data, scheme)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (attest, signature) = result.context("TPM2_GetCommandAuditDigest failed")?;

        if let Some(ref path) = self.attestation {
            let bytes = attest.marshall().context("failed to marshal TPMS_ATTEST")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing attestation to {}", path.display()))?;
            info!("audit attestation saved to {}", path.display());
        }

        if let Some(ref path) = self.signature {
            let bytes = signature
                .marshall()
                .context("failed to marshal TPMT_SIGNATURE")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing signature to {}", path.display()))?;
            info!("signature saved to {}", path.display());
        }

        info!("command audit digest retrieved");
        Ok(())
    }
}
