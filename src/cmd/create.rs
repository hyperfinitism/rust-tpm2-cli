// SPDX-License-Identifier: Apache-2.0

use log::info;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    Auth, Data, Digest, EccScheme, HashScheme, KeyDerivationFunctionScheme, KeyedHashScheme,
    PcrSelectionList, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, SensitiveData,
};
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct CreateCmd {
    /// Parent key context (file:<path> or hex:<handle>)
    #[arg(short = 'C', long = "parent-context", value_parser = parse_context_source)]
    pub parent_context: ContextSource,

    /// Key algorithm (rsa, ecc, keyedhash, hmac)
    #[arg(short = 'G', long = "key-algorithm", default_value = "rsa", value_parser = parse::parse_create_algorithm)]
    pub algorithm: parse::CreateAlgorithm,

    /// Hash algorithm
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Authorization value for the new key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Authorization value for the parent key
    #[arg(short = 'P', long = "parent-auth", value_parser = parse::parse_auth)]
    pub parent_auth: Option<Auth>,

    /// Input public template (marshaled TPM2B_PUBLIC)
    #[arg(long = "template")]
    pub template: Option<PathBuf>,

    /// Output file for the private portion
    #[arg(short = 'r', long = "private")]
    pub private_out: Option<PathBuf>,

    /// Output file for the public portion
    #[arg(short = 'u', long = "public")]
    pub public_out: Option<PathBuf>,

    /// Output file for the creation hash
    #[arg(long = "creation-hash")]
    pub creation_hash_out: Option<PathBuf>,

    /// Output file for the creation ticket
    #[arg(long = "creation-ticket")]
    pub creation_ticket_out: Option<PathBuf>,

    /// RSA key size in bits
    #[arg(long = "key-size", default_value = "2048", value_parser = parse::parse_rsa_key_bits)]
    pub key_size: RsaKeyBits,

    /// ECC curve (nistp256, nistp384, nistp521, sm2p256, etc.)
    #[arg(long = "ecc-curve", default_value = "nistp256", value_parser = parse::parse_ecc_curve)]
    pub ecc_curve: EccCurve,

    /// Input file with data to seal (for keyedhash with null scheme)
    #[arg(short = 'i', long = "seal-data")]
    pub seal_data: Option<PathBuf>,

    /// Outside info data (hex:<hex> or file:<path>)
    #[arg(short = 'q', long = "outside-info", value_parser = parse::parse_data)]
    pub outside_info: Option<Data>,

    /// Creation PCR selection (e.g. sha256:0,1,2)
    #[arg(short = 'l', long = "creation-pcr", value_parser = parse::parse_pcr_selection)]
    pub creation_pcr: Option<PcrSelectionList>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl CreateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let parent_handle = load_key_from_source(&mut ctx, &self.parent_context)?;
        if let Some(auth) = &self.parent_auth {
            ctx.tr_set_auth(parent_handle.into(), auth.clone())
                .context("failed to set parent key authorization")?;
        }
        let public = match &self.template {
            Some(path) => {
                let bytes = std::fs::read(path)
                    .with_context(|| format!("reading public template from {}", path.display()))?;
                Public::unmarshall(&bytes).context("invalid TPM2B_PUBLIC template")?
            }
            None => build_child_public(
                self.algorithm,
                self.hash_algorithm,
                self.key_size,
                self.ecc_curve,
            )?,
        };
        let sensitive_data = match &self.seal_data {
            Some(path) => {
                let data = std::fs::read(path)
                    .with_context(|| format!("reading seal data from {}", path.display()))?;
                Some(
                    SensitiveData::try_from(data)
                        .map_err(|e| anyhow::anyhow!("seal data too large: {e}"))?,
                )
            }
            None => None,
        };

        let session_path = self.session.as_deref();
        let result = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.create(
                parent_handle,
                public.clone(),
                self.auth.clone(),
                sensitive_data.clone(),
                self.outside_info.clone(),
                self.creation_pcr.clone(),
            )
        })
        .context("TPM2_Create failed")?;

        info!("key created successfully");

        if let Some(ref path) = self.private_out {
            let bytes = result.out_private.as_bytes();
            std::fs::write(path, bytes)?;
            info!("private portion saved to {}", path.display());
        }

        if let Some(ref path) = self.public_out {
            let pub_bytes = result
                .out_public
                .marshall()
                .context("failed to marshal public")?;
            std::fs::write(path, &pub_bytes)?;
            info!("public portion saved to {}", path.display());
        }

        if let Some(ref path) = self.creation_hash_out {
            std::fs::write(path, result.creation_hash.as_bytes())?;
            info!("creation hash saved to {}", path.display());
        }

        if let Some(ref path) = self.creation_ticket_out {
            std::fs::write(
                path,
                crate::ticket::marshall_ticket(&result.creation_ticket),
            )?;
            info!("creation ticket saved to {}", path.display());
        }

        Ok(())
    }
}

fn build_child_public(
    alg: parse::CreateAlgorithm,
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    key_size: RsaKeyBits,
    ecc_curve: EccCurve,
) -> anyhow::Result<Public> {
    match alg {
        parse::CreateAlgorithm::Rsa => build_rsa_signing_public(hash_alg, key_size),
        parse::CreateAlgorithm::Ecc => build_ecc_signing_public(hash_alg, ecc_curve),
        parse::CreateAlgorithm::Hmac => build_hmac_public(hash_alg),
        parse::CreateAlgorithm::KeyedHash => build_sealed_public(hash_alg),
    }
}

fn build_rsa_signing_public(
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    key_size: RsaKeyBits,
) -> anyhow::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .context("failed to build object attributes")?;

    let params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaSsa(HashScheme::new(hash_alg)))
        .with_key_bits(key_size)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(true)
        .build()
        .context("failed to build RSA parameters")?;

    PublicBuilder::new()
        .with_name_hashing_algorithm(hash_alg)
        .with_object_attributes(attributes)
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_rsa_parameters(params)
        .with_rsa_unique_identifier(Default::default())
        .build()
        .context("failed to build RSA public")
}

fn build_ecc_signing_public(
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    ecc_curve: EccCurve,
) -> anyhow::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .context("failed to build object attributes")?;

    let params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(hash_alg)))
        .with_curve(ecc_curve)
        .with_is_signing_key(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .context("failed to build ECC parameters")?;

    PublicBuilder::new()
        .with_name_hashing_algorithm(hash_alg)
        .with_object_attributes(attributes)
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(Default::default())
        .build()
        .context("failed to build ECC public")
}

fn build_hmac_public(
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
) -> anyhow::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .context("failed to build object attributes")?;

    let params = PublicKeyedHashParameters::new(KeyedHashScheme::Hmac {
        hmac_scheme: HashScheme::new(hash_alg).into(),
    });

    PublicBuilder::new()
        .with_name_hashing_algorithm(hash_alg)
        .with_object_attributes(attributes)
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_keyed_hash_parameters(params)
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .context("failed to build HMAC key public")
}

fn build_sealed_public(
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
) -> anyhow::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .context("failed to build object attributes")?;

    let params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);

    PublicBuilder::new()
        .with_name_hashing_algorithm(hash_alg)
        .with_object_attributes(attributes)
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_keyed_hash_parameters(params)
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .context("failed to build sealed data public")
}
