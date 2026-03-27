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
    Auth, Data, EccScheme, KeyDerivationFunctionScheme, PcrSelectionList, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    SymmetricDefinitionObject,
};

use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::reserved_handles::Hierarchy;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;

/// Create a primary key under a hierarchy.
#[derive(Parser)]
pub struct CreatePrimaryCmd {
    /// Hierarchy (o/owner, p/platform, e/endorsement, n/null)
    #[arg(short = 'C', long = "hierarchy", default_value = "o", value_parser = parse::parse_hierarchy)]
    pub hierarchy: Hierarchy,

    /// Key algorithm (rsa, ecc)
    #[arg(short = 'G', long = "key-algorithm", default_value = "rsa")]
    pub algorithm: String,

    /// Hash algorithm (sha1, sha256, sha384, sha512)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Authorization value for the key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Output context file for the created primary key
    #[arg(short = 'c', long = "context")]
    pub context: Option<PathBuf>,

    /// RSA key size in bits (default: 2048)
    #[arg(long = "key-size", default_value = "2048")]
    pub key_size: u16,

    /// ECC curve (nistp256, nistp384, nistp521, sm2p256, etc.)
    #[arg(long = "ecc-curve", default_value = "nistp256", value_parser = parse::parse_ecc_curve)]
    pub ecc_curve: EccCurve,

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

impl CreatePrimaryCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let public = build_public(
            &self.algorithm,
            self.hash_algorithm,
            self.key_size,
            self.ecc_curve,
        )?;

        let session_path = self.session.as_deref();
        let result = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.create_primary(
                self.hierarchy,
                public.clone(),
                self.auth.clone(),
                None, // initial_data
                self.outside_info.clone(),
                self.creation_pcr.clone(),
            )
        })
        .context("TPM2_CreatePrimary failed")?;

        info!("handle: 0x{:08x}", u32::from(result.key_handle));

        // Save context if requested
        if let Some(ref path) = self.context {
            let saved = ctx
                .context_save(result.key_handle.into())
                .context("context_save failed")?;
            let json = serde_json::to_string(&saved)?;
            std::fs::write(path, json)?;
            info!("context saved to {}", path.display());
        }

        Ok(())
    }
}

fn build_public(
    alg: &str,
    hash_alg: tss_esapi::interface_types::algorithm::HashingAlgorithm,
    key_size: u16,
    ecc_curve: EccCurve,
) -> anyhow::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .context("failed to build object attributes")?;

    let builder = PublicBuilder::new()
        .with_name_hashing_algorithm(hash_alg)
        .with_object_attributes(attributes);

    match alg.to_lowercase().as_str() {
        "rsa" => {
            let bits = match key_size {
                1024 => RsaKeyBits::Rsa1024,
                2048 => RsaKeyBits::Rsa2048,
                3072 => RsaKeyBits::Rsa3072,
                4096 => RsaKeyBits::Rsa4096,
                _ => bail!("unsupported RSA key size: {key_size}"),
            };
            let params = PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(bits)
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
                .context("failed to build RSA public")
        }
        "ecc" => {
            let params = PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::Null)
                .with_curve(ecc_curve)
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
                .context("failed to build ECC public")
        }
        _ => bail!("unsupported key algorithm: {alg}"),
    }
}
