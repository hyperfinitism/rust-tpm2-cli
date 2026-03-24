// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::{Hierarchy, HierarchyAuth};
use tss_esapi::structures::{
    Digest, EccScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;

/// TCG profile-compliant EK auth policy digest (SHA-256).
///
/// This is the well-known policy digest for `PolicySecret(TPM_RH_ENDORSEMENT)`,
/// required by the default EK templates in the TCG EK Credential Profile.
const EK_AUTH_POLICY_SHA256: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

/// Create a TCG-compliant endorsement key (EK).
///
/// Generates an EK as the primary object of the endorsement hierarchy.  The
/// key can be saved as a transient context file or persisted directly to a
/// permanent handle.
#[derive(Parser)]
pub struct CreateEkCmd {
    /// Key algorithm (rsa, ecc)
    #[arg(short = 'G', long = "key-algorithm", default_value = "rsa")]
    pub algorithm: String,

    /// Endorsement hierarchy auth value
    #[arg(short = 'P', long = "eh-auth")]
    pub eh_auth: Option<String>,

    /// Owner hierarchy auth value (required when persisting)
    #[arg(short = 'w', long = "owner-auth")]
    pub owner_auth: Option<String>,

    /// Output context file path
    #[arg(short = 'c', long = "ek-context", required = true)]
    pub ek_context: PathBuf,

    /// Output file for the public portion (TPM2B_PUBLIC, marshaled binary)
    #[arg(short = 'u', long = "public")]
    pub public: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl CreateEkCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let public_template = build_ek_public(&self.algorithm)?;

        // Set endorsement hierarchy auth if provided.
        if let Some(ref a) = self.eh_auth {
            let auth = parse::parse_auth(a)?;
            let hier_obj: ObjectHandle = HierarchyAuth::Endorsement.into();
            ctx.tr_set_auth(hier_obj, auth)
                .context("failed to set endorsement hierarchy auth")?;
        }

        let session_path = self.session.as_deref();
        let result = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.create_primary(
                Hierarchy::Endorsement,
                public_template.clone(),
                None, // EK uses policy auth, not password
                None,
                None,
                None,
            )
        })
        .context("TPM2_CreatePrimary failed")?;

        info!("handle: 0x{:08x}", u32::from(result.key_handle));

        // Write public portion if requested.
        if let Some(ref path) = self.public {
            let pub_bytes = result
                .out_public
                .marshall()
                .context("failed to marshal public key")?;
            std::fs::write(path, &pub_bytes)
                .with_context(|| format!("writing public key to {}", path.display()))?;
            info!("public key saved to {}", path.display());
        }

        // Save EK context.
        let saved = ctx
            .context_save(result.key_handle.into())
            .context("context_save failed")?;
        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.ek_context, json)
            .with_context(|| format!("writing EK context to {}", self.ek_context.display()))?;
        info!("EK context saved to {}", self.ek_context.display());

        Ok(())
    }
}

fn build_ek_public(alg: &str) -> anyhow::Result<Public> {
    let auth_policy = Digest::try_from(EK_AUTH_POLICY_SHA256.to_vec())
        .map_err(|e| anyhow::anyhow!("invalid auth policy: {e}"))?;

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_admin_with_policy(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .context("failed to build object attributes")?;

    let builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(auth_policy);

    match alg.to_lowercase().as_str() {
        "rsa" => {
            let params = PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_decryption_key(true)
                .with_restricted(true)
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .build()
                .context("failed to build RSA parameters")?;

            builder
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_rsa_parameters(params)
                .with_rsa_unique_identifier(Default::default())
                .build()
                .context("failed to build RSA EK public template")
        }
        "ecc" => {
            let params = PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .context("failed to build ECC parameters")?;

            builder
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_ecc_parameters(params)
                .with_ecc_unique_identifier(Default::default())
                .build()
                .context("failed to build ECC EK public template")
        }
        _ => bail!("unsupported EK algorithm: {alg}; supported: rsa, ecc"),
    }
}
