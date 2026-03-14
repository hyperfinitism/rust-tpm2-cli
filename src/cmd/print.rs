// SPDX-License-Identifier: Apache-2.0

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use tss_esapi::structures::{Attest, AttestInfo, Public, PublicBuffer};
use tss_esapi::traits::UnMarshall;
use tss_esapi::utils::TpmsContext;

/// Decode and display a TPM data structure.
///
/// Reads a binary TPM structure from a file (or stdin) and prints a
/// human-readable representation to stdout.
#[derive(Parser)]
pub struct PrintCmd {
    /// Structure type to decode
    #[arg(short = 't', long = "type")]
    pub structure_type: String,

    /// Input file (default: stdin)
    #[arg()]
    pub input: Option<PathBuf>,
}

impl PrintCmd {
    pub fn execute(&self, _global: &crate::cli::GlobalOpts) -> anyhow::Result<()> {
        let data = read_input(&self.input)?;

        match self.structure_type.to_lowercase().as_str() {
            "tpms_attest" => print_attest(&data)?,
            "tpms_context" => print_context(&data)?,
            "tpm2b_public" => print_tpm2b_public(&data)?,
            "tpmt_public" => print_tpmt_public(&data)?,
            other => bail!(
                "unsupported type: {other}\n\
                 supported types: TPMS_ATTEST, TPMS_CONTEXT, TPM2B_PUBLIC, TPMT_PUBLIC"
            ),
        }

        Ok(())
    }
}

fn read_input(path: &Option<PathBuf>) -> anyhow::Result<Vec<u8>> {
    match path {
        Some(p) => std::fs::read(p).with_context(|| format!("reading input: {}", p.display())),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("reading stdin")?;
            Ok(buf)
        }
    }
}

fn print_attest(data: &[u8]) -> anyhow::Result<()> {
    let attest = Attest::unmarshall(data)
        .map_err(|e| anyhow::anyhow!("failed to unmarshal TPMS_ATTEST: {e}"))?;

    println!("type: {:?}", attest.attestation_type());
    println!(
        "qualified_signer: {}",
        hex::encode(attest.qualified_signer().value())
    );
    println!("extra_data: {}", hex::encode(attest.extra_data().value()));
    println!("clock_info:");
    let ci = attest.clock_info();
    println!("  clock: {}", ci.clock());
    println!("  reset_count: {}", ci.reset_count());
    println!("  restart_count: {}", ci.restart_count());
    println!("  safe: {}", if ci.safe() { "yes" } else { "no" });
    println!("firmware_version: 0x{:016x}", attest.firmware_version());

    match attest.attested() {
        AttestInfo::Quote { info } => {
            println!("attested:");
            println!("  type: quote");
            println!("  pcr_digest: {}", hex::encode(info.pcr_digest().value()));
            println!("  pcr_selection: {:?}", info.pcr_selection());
        }
        AttestInfo::Certify { info } => {
            println!("attested:");
            println!("  type: certify");
            println!("  name: {}", hex::encode(info.name().value()));
            println!(
                "  qualified_name: {}",
                hex::encode(info.qualified_name().value())
            );
        }
        AttestInfo::Creation { info } => {
            println!("attested:");
            println!("  type: creation");
            println!("  object_name: {}", hex::encode(info.object_name().value()));
            println!(
                "  creation_hash: {}",
                hex::encode(info.creation_hash().value())
            );
        }
        AttestInfo::Time { info } => {
            println!("attested:");
            println!("  type: time");
            let ti = info.time_info();
            println!("  time: {}", ti.time());
            println!("  clock: {}", ti.clock_info().clock());
            println!("  firmware_version: 0x{:016x}", info.firmware_version());
        }
        other => {
            println!("attested:");
            println!("  type: {:?}", std::mem::discriminant(other));
        }
    }

    Ok(())
}

fn print_context(data: &[u8]) -> anyhow::Result<()> {
    let ctx: TpmsContext =
        serde_json::from_slice(data).context("failed to deserialize TPMS_CONTEXT")?;
    println!("{ctx:#?}");
    Ok(())
}

fn print_tpm2b_public(data: &[u8]) -> anyhow::Result<()> {
    let buf = PublicBuffer::unmarshall(data)
        .map_err(|e| anyhow::anyhow!("failed to unmarshal TPM2B_PUBLIC: {e}"))?;
    let public: Public = buf
        .try_into()
        .map_err(|e: tss_esapi::Error| anyhow::anyhow!("failed to decode Public: {e}"))?;
    print_public(&public);
    Ok(())
}

fn print_tpmt_public(data: &[u8]) -> anyhow::Result<()> {
    let public = Public::unmarshall(data)
        .map_err(|e| anyhow::anyhow!("failed to unmarshal TPMT_PUBLIC: {e}"))?;
    print_public(&public);
    Ok(())
}

fn print_public(public: &Public) {
    match public {
        Public::Rsa {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique,
        } => {
            println!("type: rsa");
            println!("name_hash_algorithm: {name_hashing_algorithm:?}");
            println!("object_attributes: {object_attributes:?}");
            println!("auth_policy: {}", hex::encode(auth_policy.value()));
            println!("parameters: {parameters:?}");
            println!("modulus: {}", hex::encode(unique.value()));
        }
        Public::Ecc {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique,
        } => {
            println!("type: ecc");
            println!("name_hash_algorithm: {name_hashing_algorithm:?}");
            println!("object_attributes: {object_attributes:?}");
            println!("auth_policy: {}", hex::encode(auth_policy.value()));
            println!("parameters: {parameters:?}");
            println!("x: {}", hex::encode(unique.x().value()));
            println!("y: {}", hex::encode(unique.y().value()));
        }
        Public::KeyedHash {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique,
        } => {
            println!("type: keyedhash");
            println!("name_hash_algorithm: {name_hashing_algorithm:?}");
            println!("object_attributes: {object_attributes:?}");
            println!("auth_policy: {}", hex::encode(auth_policy.value()));
            println!("parameters: {parameters:?}");
            println!("unique: {}", hex::encode(unique.value()));
        }
        Public::SymCipher {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique,
        } => {
            println!("type: symcipher");
            println!("name_hash_algorithm: {name_hashing_algorithm:?}");
            println!("object_attributes: {object_attributes:?}");
            println!("auth_policy: {}", hex::encode(auth_policy.value()));
            println!("parameters: {parameters:?}");
            println!("unique: {}", hex::encode(unique.value()));
        }
    }
}
