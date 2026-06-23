// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Data};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::load_optional_auth_session;
#[derive(Parser)]
pub struct GetTimeCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Authorization value for the signing key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Authorization value for the endorsement hierarchy
    #[arg(long = "privacy-auth", value_parser = parse::parse_auth)]
    pub privacy_auth: Option<Auth>,

    /// Hash algorithm for signing
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null", value_parser = parse::parse_signature_scheme_kind)]
    pub scheme: parse::SignatureSchemeKind,

    /// Qualifying data (hex:<hex_bytes> or file:<path>)
    #[arg(short = 'q', long = "qualification", value_parser = parse::parse_qualification)]
    pub qualification: Option<parse::Qualification>,

    /// Output file for the attestation data
    #[arg(short = 'o', long = "attestation")]
    pub attestation: Option<PathBuf>,

    /// Output file for the signature
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,

    /// Session context file for privacy administrator authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,

    /// Session context file for signing key authorization
    #[arg(long = "signing-session")]
    pub signing_session: Option<PathBuf>,
}

impl GetTimeCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let signing_key = load_key_from_source(&mut ctx, &self.context)?;
        let scheme = self.scheme.with_hash(self.hash_algorithm);

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(signing_key.into(), auth.clone())
                .context("tr_set_auth failed")?;
        }
        if let Some(auth) = &self.privacy_auth {
            ctx.tr_set_auth(ObjectHandle::Endorsement, auth.clone())
                .context("failed to set endorsement hierarchy authorization")?;
        }

        let qualifying_data = match &self.qualification {
            Some(bytes) => Data::try_from(bytes.as_slice().to_vec())
                .map_err(|e| anyhow::anyhow!("qualifying data: {e}"))?,
            None => Data::default(),
        };
        let privacy_session = load_optional_auth_session(&mut ctx, self.session.as_deref())?;
        let signing_session =
            load_optional_auth_session(&mut ctx, self.signing_session.as_deref())?;
        ctx.set_sessions((Some(privacy_session), Some(signing_session), None));
        let result = ctx
            .get_time(signing_key, qualifying_data.clone(), scheme)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (attest, signature) = result.context("TPM2_GetTime failed")?;

        if let Some(ref path) = self.attestation {
            let bytes = attest.marshall().context("failed to marshal TPMS_ATTEST")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing attestation to {}", path.display()))?;
            info!("attestation saved to {}", path.display());
        }

        if let Some(ref path) = self.signature {
            let bytes = signature
                .marshall()
                .context("failed to marshal TPMT_SIGNATURE")?;
            std::fs::write(path, &bytes)
                .with_context(|| format!("writing signature to {}", path.display()))?;
            info!("signature saved to {}", path.display());
        }

        info!("gettime succeeded");
        Ok(())
    }
}
