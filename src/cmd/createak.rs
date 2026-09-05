// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
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
    Auth, Data, EccScheme, HashScheme, KeyDerivationFunctionScheme, PcrSelectionList, Public,
    PublicBuilder, PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SensitiveData, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::{flush_policy_session, start_ek_policy_session};
#[derive(Parser)]
pub struct CreateAkCmd {
    /// EK context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "ek-context", value_parser = parse_context_source)]
    pub ek_context: ContextSource,

    /// Output context file for the attestation key
    #[arg(short = 'c', long = "ak-context")]
    pub ak_context: PathBuf,

    /// Key algorithm (ecc, rsa, keyedhash)
    #[arg(short = 'G', long = "key-algorithm", default_value = "rsa", value_parser = parse::parse_asymmetric_algorithm)]
    pub algorithm: parse::AsymmetricAlgorithm,

    /// Hash algorithm
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Authorization value for the endorsement hierarchy
    #[arg(short = 'P', long = "eh-auth", value_parser = parse::parse_auth)]
    pub eh_auth: Option<Auth>,

    /// Authorization value for the attestation key
    #[arg(short = 'p', long = "ak-auth", value_parser = parse::parse_auth)]
    pub ak_auth: Option<Auth>,

    /// Input public template (marshaled TPM2B_PUBLIC)
    #[arg(long = "template")]
    pub template: Option<PathBuf>,

    /// Sensitive data included in the new object's sensitive area
    #[arg(long = "sensitive-data", value_parser = parse::parse_sensitive_data)]
    pub sensitive_data: Option<SensitiveData>,

    /// Outside info data (hex:<hex> or file:<path>)
    #[arg(short = 'q', long = "outside-info", value_parser = parse::parse_data)]
    pub outside_info: Option<Data>,

    /// Creation PCR selection (e.g. sha256:0,1,2)
    #[arg(short = 'l', long = "creation-pcr", value_parser = parse::parse_pcr_selection)]
    pub creation_pcr: Option<PcrSelectionList>,

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
        let mut ctx = create_context(global.tcti.as_ref())?;

        let ak_template = match &self.template {
            Some(path) => {
                let bytes = std::fs::read(path)
                    .with_context(|| format!("reading public template from {}", path.display()))?;
                Public::unmarshall(&bytes).context("invalid TPM2B_PUBLIC template")?
            }
            None => build_ak_public(self.algorithm, self.hash_algorithm)?,
        };

        let ek_handle = load_key_from_source(&mut ctx, &self.ek_context)?;
        if let Some(ref auth) = self.eh_auth {
            let eh_obj: ObjectHandle = HierarchyAuth::Endorsement.into();
            ctx.tr_set_auth(eh_obj, auth.clone())
                .context("failed to set endorsement hierarchy auth")?;
        }
        let policy_session = start_ek_policy_session(&mut ctx)?;
        ctx.set_sessions((Some(AuthSession::PolicySession(policy_session)), None, None));
        let result = ctx
            .create(
                ek_handle,
                ak_template.clone(),
                self.ak_auth.clone(),
                self.sensitive_data.clone(),
                self.outside_info.clone(),
                self.creation_pcr.clone(),
            )
            .context("TPM2_Create failed")?;
        ctx.clear_sessions();

        flush_policy_session(&mut ctx, policy_session)?;
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
        let (_, ak_name_obj, _) = ctx
            .execute_without_session(|ctx| ctx.read_public(ak_handle))
            .context("TPM2_ReadPublic failed")?;
        info!("AK name: 0x{}", hex::encode(ak_name_obj.value()));
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

fn build_ak_public(
    alg: parse::AsymmetricAlgorithm,
    hash_alg: HashingAlgorithm,
) -> anyhow::Result<Public> {
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

    match alg {
        parse::AsymmetricAlgorithm::Rsa => {
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
        parse::AsymmetricAlgorithm::Ecc => {
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
    }
}
