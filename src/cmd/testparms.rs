// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    PublicKeyedHashParameters, PublicParameters, PublicRsaParameters, RsaExponent, RsaScheme,
    SymmetricCipherParameters, SymmetricDefinitionObject,
};

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Check if the TPM supports a given algorithm combination.
///
/// Wraps TPM2_TestParms.
#[derive(Parser)]
pub struct TestParmsCmd {
    /// Algorithm parameters to test. Format: <type>
    /// Supported: rsa, rsa2048, rsa3072, rsa4096,
    ///            aes, aes128, aes192, aes256,
    ///            keyedhash, hmac, xor
    #[arg()]
    pub parameters: String,
}

impl TestParmsCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let params = parse_public_params(&self.parameters)?;

        match ctx.execute_without_session(|ctx| ctx.test_parms(params)) {
            Ok(()) => {
                info!("parameters '{}' are supported", self.parameters);
                println!("supported");
            }
            Err(e) => {
                println!("not supported: {e}");
            }
        }

        Ok(())
    }
}

fn parse_public_params(s: &str) -> anyhow::Result<PublicParameters> {
    match s.to_lowercase().as_str() {
        "rsa" | "rsa2048" => Ok(PublicParameters::Rsa(PublicRsaParameters::new(
            SymmetricDefinitionObject::Null,
            RsaScheme::Null,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        ))),
        "rsa3072" => Ok(PublicParameters::Rsa(PublicRsaParameters::new(
            SymmetricDefinitionObject::Null,
            RsaScheme::Null,
            RsaKeyBits::Rsa3072,
            RsaExponent::default(),
        ))),
        "rsa4096" => Ok(PublicParameters::Rsa(PublicRsaParameters::new(
            SymmetricDefinitionObject::Null,
            RsaScheme::Null,
            RsaKeyBits::Rsa4096,
            RsaExponent::default(),
        ))),
        "keyedhash" | "hmac" | "xor" => Ok(PublicParameters::KeyedHash(
            PublicKeyedHashParameters::new(tss_esapi::structures::KeyedHashScheme::HMAC_SHA_256),
        )),
        "aes" | "aes128" => Ok(PublicParameters::SymCipher(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::Aes {
                key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            },
        ))),
        "aes256" => Ok(PublicParameters::SymCipher(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::Aes {
                key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes256,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            },
        ))),
        _ => anyhow::bail!("unsupported parameter set: {s}"),
    }
}
