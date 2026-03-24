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
use tss_esapi::interface_types::reserved_handles::HierarchyAuth;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    EccScheme, HashScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::{flush_policy_session, start_ek_policy_session};

/// Create an attestation key (AK) under an endorsement key.
///
/// The AK is a restricted signing key created as a child of the specified
/// EK.  Its name can be used with `tpm2 makecredential` / `activatecredential`
/// for remote attestation flows.
#[derive(Parser)]
pub struct CreateAkCmd {
    /// EK context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "ek-context", value_parser = parse_context_source)]
    pub ek_context: ContextSource,

    /// Output context file for the attestation key
    #[arg(short = 'c', long = "ak-context")]
    pub ak_context: PathBuf,

    /// Key algorithm (ecc, rsa, keyedhash)
    #[arg(short = 'G', long = "key-algorithm", default_value = "rsa")]
    pub algorithm: String,

    /// Hash algorithm (sha1, sha256, sha384, sha512)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Endorsement hierarchy auth value
    #[arg(short = 'P', long = "eh-auth")]
    pub eh_auth: Option<String>,

    /// Auth value for the attestation key
    #[arg(short = 'p', long = "ak-auth")]
    pub ak_auth: Option<String>,

    /// Output file for AK public portion (TPM2B_PUBLIC, marshaled binary)
    #[arg(short = 'u', long = "public")]
    pub public: Option<PathBuf>,

    /// Output file for AK private portion (TPM2B_PRIVATE, marshaled binary)
    #[arg(short = 'r', long = "private")]
    pub private: Option<PathBuf>,

    /// Output file for AK name (binary)
    #[arg(short = 'n', long = "ak-name")]
    pub ak_name: Option<PathBuf>,
}

impl CreateAkCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let ak_template = build_ak_public(&self.algorithm, hash_alg)?;

        let ek_handle = load_key_from_source(&mut ctx, &self.ek_context)?;

        let ak_auth = match &self.ak_auth {
            Some(a) => Some(parse::parse_auth(a)?),
            None => None,
        };

        // Set endorsement hierarchy auth if provided.
        if let Some(ref a) = self.eh_auth {
            let auth = parse::parse_auth(a)?;
            let eh_obj: ObjectHandle = HierarchyAuth::Endorsement.into();
            ctx.tr_set_auth(eh_obj, auth)
                .context("failed to set endorsement hierarchy auth")?;
        }

        // --- Create AK under EK (requires EK policy session) ---
        let policy_session = start_ek_policy_session(&mut ctx)?;
        ctx.set_sessions((Some(AuthSession::PolicySession(policy_session)), None, None));
        let result = ctx
            .create(
                ek_handle,
                ak_template.clone(),
                ak_auth.clone(),
                None,
                None,
                None,
            )
            .context("TPM2_Create failed")?;
        ctx.clear_sessions();

        flush_policy_session(&mut ctx, policy_session)?;

        // --- Load AK under EK (requires a fresh policy session) ---
        let policy_session = start_ek_policy_session(&mut ctx)?;
        ctx.set_sessions((Some(AuthSession::PolicySession(policy_session)), None, None));
        let ak_handle = ctx
            .load(
                ek_handle,
                result.out_private.clone(),
                result.out_public.clone(),
            )
            .context("TPM2_Load failed")?;
        ctx.clear_sessions();

        flush_policy_session(&mut ctx, policy_session)?;

        info!("AK handle: 0x{:08x}", u32::from(ak_handle));

        // Read the AK name from the TPM.
        let (_, ak_name_obj, _) = ctx
            .execute_without_session(|ctx| ctx.read_public(ak_handle))
            .context("TPM2_ReadPublic failed")?;
        info!("AK name: 0x{}", hex::encode(ak_name_obj.value()));

        // Save outputs.
        if let Some(ref path) = self.public {
            let pub_bytes = result
                .out_public
                .marshall()
                .context("failed to marshal public")?;
            std::fs::write(path, &pub_bytes)
                .with_context(|| format!("writing public to {}", path.display()))?;
            info!("public saved to {}", path.display());
        }

        if let Some(ref path) = self.private {
            std::fs::write(path, result.out_private.as_bytes())
                .with_context(|| format!("writing private to {}", path.display()))?;
            info!("private saved to {}", path.display());
        }

        if let Some(ref path) = self.ak_name {
            std::fs::write(path, ak_name_obj.value())
                .with_context(|| format!("writing AK name to {}", path.display()))?;
            info!("AK name saved to {}", path.display());
        }

        // Save AK context.
        let saved = ctx
            .context_save(ak_handle.into())
            .context("context_save failed")?;
        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.ak_context, json)
            .with_context(|| format!("writing AK context to {}", self.ak_context.display()))?;
        info!("AK context saved to {}", self.ak_context.display());

        Ok(())
    }
}

fn build_ak_public(alg: &str, hash_alg: HashingAlgorithm) -> anyhow::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .build()
        .context("failed to build object attributes")?;

    let builder = PublicBuilder::new()
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes);

    match alg.to_lowercase().as_str() {
        "rsa" => {
            let params = PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(hash_alg)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(true)
                .with_restricted(true)
                .with_symmetric(SymmetricDefinitionObject::Null)
                .build()
                .context("failed to build RSA parameters")?;

            builder
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_rsa_parameters(params)
                .with_rsa_unique_identifier(Default::default())
                .build()
                .context("failed to build RSA AK public")
        }
        "ecc" => {
            let params = PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(hash_alg)))
                .with_curve(EccCurve::NistP256)
                .with_is_signing_key(true)
                .with_restricted(true)
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .context("failed to build ECC parameters")?;

            builder
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_ecc_parameters(params)
                .with_ecc_unique_identifier(Default::default())
                .build()
                .context("failed to build ECC AK public")
        }
        _ => bail!("unsupported AK algorithm: {alg}; supported: rsa, ecc"),
    }
}
