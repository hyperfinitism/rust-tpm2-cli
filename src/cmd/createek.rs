// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::data_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::reserved_handles::{Hierarchy, HierarchyAuth, Provision};
use tss_esapi::structures::{
    Auth, Data, Digest, EccScheme, KeyDerivationFunctionScheme, PcrSelectionList, Public,
    PublicBuilder, PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SensitiveData, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::{execute_with_command_session, load_command_session};

/// TCG profile-compliant EK auth policy digest (SHA-256).
///
/// This is the well-known policy digest for `PolicySecret(TPM_RH_ENDORSEMENT)`,
/// required by the default EK templates in the TCG EK Credential Profile.
const EK_AUTH_POLICY_SHA256: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];
#[derive(Parser)]
pub struct CreateEkCmd {
    /// Key algorithm (rsa, ecc)
    #[arg(short = 'G', long = "key-algorithm", default_value = "rsa", value_parser = parse::parse_asymmetric_algorithm)]
    pub algorithm: parse::AsymmetricAlgorithm,

    /// Authorization value for the endorsement hierarchy
    #[arg(short = 'P', long = "eh-auth", value_parser = parse::parse_auth)]
    pub eh_auth: Option<Auth>,

    /// Authorization value for the owner hierarchy
    #[arg(short = 'w', long = "owner-auth", value_parser = parse::parse_auth)]
    pub owner_auth: Option<Auth>,

    /// Authorization value for the new key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub key_auth: Option<Auth>,

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

    /// Persistent handle for the new endorsement key
    #[arg(long = "persistent", value_parser = parse::parse_persistent_handle)]
    pub persistent: Option<tss_esapi::handles::PersistentTpmHandle>,

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
        let mut ctx = create_context(global.tcti.as_ref())?;

        let public_template = match &self.template {
            Some(path) => {
                let bytes = std::fs::read(path)
                    .with_context(|| format!("reading public template from {}", path.display()))?;
                Public::unmarshall(&bytes).context("invalid TPM2B_PUBLIC template")?
            }
            None => build_ek_public(self.algorithm)?,
        };
        if let Some(ref auth) = self.eh_auth {
            let hier_obj: ObjectHandle = HierarchyAuth::Endorsement.into();
            ctx.tr_set_auth(hier_obj, auth.clone())
                .context("failed to set endorsement hierarchy auth")?;
        }

        let session_path = self.session.as_deref();
        let session = load_command_session(&mut ctx, session_path)?;
        let result = execute_with_command_session(&mut ctx, session, |ctx| {
            ctx.create_primary(
                Hierarchy::Endorsement,
                public_template.clone(),
                self.key_auth.clone(),
                self.sensitive_data.clone(),
                self.outside_info.clone(),
                self.creation_pcr.clone(),
            )
        })
        .context("TPM2_CreatePrimary failed")?;

        info!("handle: 0x{:08x}", u32::from(result.key_handle));
        if let Some(persistent_handle) = self.persistent {
            if let Some(ref auth) = self.owner_auth {
                ctx.tr_set_auth(ObjectHandle::Owner, auth.clone())
                    .context("failed to set owner hierarchy auth")?;
            }
            let persistent: Persistent = persistent_handle.into();
            execute_with_command_session(&mut ctx, session, |ctx| {
                ctx.evict_control(Provision::Owner, result.key_handle.into(), persistent)
            })
            .context("TPM2_EvictControl failed")?;
            info!("EK persisted at 0x{:08x}", u32::from(persistent_handle));
        }
        if let Some(ref path) = self.public {
            let pub_bytes = result
                .out_public
                .marshall()
                .context("failed to marshal public key")?;
            std::fs::write(path, &pub_bytes)
                .with_context(|| format!("writing public key to {}", path.display()))?;
            info!("public key saved to {}", path.display());
        }
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

fn build_ek_public(alg: parse::AsymmetricAlgorithm) -> anyhow::Result<Public> {
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

    match alg {
        parse::AsymmetricAlgorithm::Rsa => {
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
        parse::AsymmetricAlgorithm::Ecc => {
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
    }
}
