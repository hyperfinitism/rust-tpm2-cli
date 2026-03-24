// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{Digest, Name, Public};
use tss_esapi::traits::UnMarshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Create a credential blob for a TPM key.
///
/// Wraps `TPM2_MakeCredential`: encrypts a caller-chosen secret so that only
/// the TPM holding the matching private key (typically an EK) can recover it,
/// and only when the correct object name (typically an AK name) is presented.
#[derive(Parser)]
pub struct MakeCredentialCmd {
    /// Public key file (TPM2B_PUBLIC, marshaled binary) used to wrap the seed
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// File containing the secret to protect
    #[arg(short = 's', long = "secret")]
    pub secret: PathBuf,

    /// File containing the name of the key the credential is bound to (binary)
    #[arg(short = 'n', long = "name")]
    pub name: PathBuf,

    /// Output credential blob file
    #[arg(short = 'o', long = "credential-blob")]
    pub credential_blob: PathBuf,
}

impl MakeCredentialCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        // Read inputs.
        let pub_bytes = std::fs::read(&self.public)
            .with_context(|| format!("reading public key: {}", self.public.display()))?;
        let secret_bytes = std::fs::read(&self.secret)
            .with_context(|| format!("reading secret: {}", self.secret.display()))?;
        let name_bytes = std::fs::read(&self.name)
            .with_context(|| format!("reading name: {}", self.name.display()))?;

        let public = Public::unmarshall(&pub_bytes).context("failed to parse TPM2B_PUBLIC")?;
        let credential =
            Digest::try_from(secret_bytes).map_err(|e| anyhow::anyhow!("invalid secret: {e}"))?;
        let object_name =
            Name::try_from(name_bytes).map_err(|e| anyhow::anyhow!("invalid name: {e}"))?;

        // Load the public key into the TPM (public-only, no private part).
        let key_handle = ctx
            .execute_without_session(|ctx| ctx.load_external(None, public.clone(), Hierarchy::Null))
            .context("TPM2_LoadExternal failed")?;

        // Make credential.
        let (id_object, encrypted_secret) = ctx
            .execute_without_session(|ctx| {
                ctx.make_credential(key_handle, credential.clone(), object_name.clone())
            })
            .context("TPM2_MakeCredential failed")?;

        // Write credential blob: [u16 id_len][id_data][u16 secret_len][secret_data].
        let id_data = id_object.as_bytes();
        let secret_data = encrypted_secret.as_bytes();
        let mut blob = Vec::with_capacity(4 + id_data.len() + secret_data.len());
        blob.extend_from_slice(&(id_data.len() as u16).to_be_bytes());
        blob.extend_from_slice(id_data);
        blob.extend_from_slice(&(secret_data.len() as u16).to_be_bytes());
        blob.extend_from_slice(secret_data);

        std::fs::write(&self.credential_blob, &blob).with_context(|| {
            format!(
                "writing credential blob to {}",
                self.credential_blob.display()
            )
        })?;
        info!(
            "credential blob saved to {}",
            self.credential_blob.display()
        );

        // Flush the externally-loaded key.
        ctx.flush_context(key_handle.into())
            .context("failed to flush loaded key")?;

        Ok(())
    }
}
