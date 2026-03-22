// SPDX-License-Identifier: Apache-2.0

use log::info;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    Digest, EccScheme, HashScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Public,
    PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, SensitiveData,
};
use tss_esapi::traits::Marshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse;
use crate::parse::parse_hex_u32;
use crate::session::execute_with_optional_session;

/// Create a child key under a parent key.
#[derive(Parser)]
pub struct CreateCmd {
    /// Parent key context file path
    #[arg(
        short = 'C',
        long = "parent-context",
        conflicts_with = "parent_context_handle"
    )]
    pub parent_context: Option<PathBuf>,

    /// Parent key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "parent-context-handle", value_parser = parse_hex_u32, conflicts_with = "parent_context")]
    pub parent_context_handle: Option<u32>,

    /// Key algorithm (rsa, ecc, keyedhash, hmac)
    #[arg(short = 'G', long = "key-algorithm", default_value = "rsa")]
    pub algorithm: String,

    /// Hash algorithm
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Authorization value for the new key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Output file for the private portion
    #[arg(short = 'r', long = "private")]
    pub private_out: Option<PathBuf>,

    /// Output file for the public portion
    #[arg(short = 'u', long = "public")]
    pub public_out: Option<PathBuf>,

    /// RSA key size in bits
    #[arg(long = "key-size", default_value = "2048")]
    pub key_size: u16,

    /// Input file with data to seal (for keyedhash with null scheme)
    #[arg(short = 'i', long = "seal-data")]
    pub seal_data: Option<PathBuf>,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl CreateCmd {
    fn parent_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.parent_context, self.parent_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --parent-context or --parent-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let parent_handle = load_key_from_source(&mut ctx, &self.parent_context_source()?)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;
        let public = build_child_public(&self.algorithm, hash_alg, self.key_size)?;

        let auth = match &self.auth {
            Some(a) => Some(parse::parse_auth(a)?),
            None => None,
        };

        // If seal data is provided, read it.
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
                auth.clone(),
                sensitive_data.clone(),
                None,
                None,
            )
        })
        .context("TPM2_Create failed")?;

        info!("key created successfully");

        if let Some(ref path) = self.private_out {
            let bytes = result.out_private.value();
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

        Ok(())
    }
}

fn build_child_public(
    alg: &str,
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    key_size: u16,
) -> anyhow::Result<Public> {
    match alg.to_lowercase().as_str() {
        "rsa" => build_rsa_signing_public(hash_alg, key_size),
        "ecc" => build_ecc_signing_public(hash_alg),
        "hmac" => build_hmac_public(hash_alg),
        "keyedhash" => build_sealed_public(hash_alg),
        _ => bail!("unsupported key algorithm: {alg} (supported: rsa, ecc, hmac, keyedhash)"),
    }
}

fn build_rsa_signing_public(
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    key_size: u16,
) -> anyhow::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .context("failed to build object attributes")?;

    let bits = match key_size {
        1024 => RsaKeyBits::Rsa1024,
        2048 => RsaKeyBits::Rsa2048,
        3072 => RsaKeyBits::Rsa3072,
        4096 => RsaKeyBits::Rsa4096,
        _ => bail!("unsupported RSA key size: {key_size}"),
    };
    let params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaSsa(HashScheme::new(hash_alg)))
        .with_key_bits(bits)
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
        .with_curve(EccCurve::NistP256)
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
    // Sealed data objects use KeyedHash with a Null scheme and no
    // sign_encrypt or sensitive_data_origin attributes.
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
