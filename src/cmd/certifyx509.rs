// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Data, MaxBuffer};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source, load_object_from_source};
use crate::output;
use crate::parse::{self, parse_context_source};
use crate::session::{
    load_optional_auth_session, load_optional_policy_or_hmac_session, save_session_to_file,
};
#[derive(Parser)]
pub struct CertifyX509Cmd {
    /// Object context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "object-context", value_parser = parse_context_source)]
    pub object_context: ContextSource,

    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "signing-key-context", value_parser = parse_context_source)]
    pub signing_key_context: ContextSource,

    /// Authorization value for the object
    #[arg(short = 'P', long = "object-auth", value_parser = parse::parse_auth)]
    pub object_auth: Option<Auth>,

    /// Authorization value for the signing key
    #[arg(short = 'p', long = "signing-key-auth", value_parser = parse::parse_auth)]
    pub signing_key_auth: Option<Auth>,

    /// Hash algorithm used by the signature scheme
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Signature scheme (rsassa, rsapss, ecdsa, null)
    #[arg(long = "scheme", default_value = "null", value_parser = parse::parse_signature_scheme_kind)]
    pub scheme: parse::SignatureSchemeKind,

    /// DER-encoded partial certificate
    #[arg(short = 'i', long = "partial-certificate")]
    pub partial_certificate: PathBuf,

    /// Output file for data added to the certificate
    #[arg(short = 'o', long = "added-to-certificate")]
    pub added_to_certificate: Option<PathBuf>,

    /// Output file for the to-be-signed certificate digest
    #[arg(short = 'd', long = "tbs-digest")]
    pub tbs_digest: Option<PathBuf>,

    /// Output file for the signature
    #[arg(short = 's', long = "signature")]
    pub signature: Option<PathBuf>,

    /// HMAC session context file for object authorization
    #[arg(short = 'S', long = "session", conflicts_with = "policy_session")]
    pub session: Option<PathBuf>,

    /// Policy session context file for object authorization
    #[arg(long = "policy-session", conflicts_with = "session")]
    pub policy_session: Option<PathBuf>,

    /// Session context file for signing key authorization
    #[arg(long = "signing-session")]
    pub signing_session: Option<PathBuf>,
}

impl CertifyX509Cmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let object = load_object_from_source(&mut ctx, &self.object_context)?;
        let signing_key = load_key_from_source(&mut ctx, &self.signing_key_context)?;

        if let Some(auth) = &self.object_auth {
            ctx.tr_set_auth(object, auth.clone())
                .context("failed to set object authorization")?;
        }
        if let Some(auth) = &self.signing_key_auth {
            ctx.tr_set_auth(signing_key.into(), auth.clone())
                .context("failed to set signing key authorization")?;
        }

        let partial = std::fs::read(&self.partial_certificate).with_context(|| {
            format!(
                "reading partial certificate from {}",
                self.partial_certificate.display()
            )
        })?;
        let partial = MaxBuffer::try_from(partial)
            .map_err(|e| anyhow::anyhow!("partial certificate too large: {e}"))?;
        let first_session = load_optional_policy_or_hmac_session(
            &mut ctx,
            self.policy_session.as_deref(),
            self.session.as_deref(),
        )?;
        let second_session = load_optional_auth_session(&mut ctx, self.signing_session.as_deref())?;

        ctx.set_sessions((Some(first_session), Some(second_session), None));
        let result = ctx
            .certify_x509(
                object,
                signing_key,
                Data::default(),
                self.scheme.with_hash(self.hash_algorithm),
                partial,
            )
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (added, digest, signature) = result.context("TPM2_CertifyX509 failed")?;

        if let Some(path) = self.policy_session.as_deref().or(self.session.as_deref()) {
            save_session_to_file(&mut ctx, first_session, path)?;
        }
        if let Some(path) = self.signing_session.as_deref() {
            save_session_to_file(&mut ctx, second_session, path)?;
        }

        if let Some(path) = &self.added_to_certificate {
            output::write_to_file(path, added.as_bytes())?;
        }
        if let Some(path) = &self.tbs_digest {
            output::write_to_file(path, digest.as_bytes())?;
        }
        if let Some(path) = &self.signature {
            output::write_to_file(path, &signature.marshall()?)?;
        }

        info!("X.509 certificate components generated");
        Ok(())
    }
}
