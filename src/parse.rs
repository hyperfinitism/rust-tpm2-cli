// SPDX-License-Identifier: Apache-2.0

//! Pure CLI argument parsers.
//!
//! Every function in this module converts a CLI string into a typed value
//! without touching a TPM context.  Functions that need a [`tss_esapi::Context`]
//! live in [`crate::handle`] or [`crate::session`].
//!
//! All public parse functions return `Result<T, E>` where `E` is either
//! [`String`] or [`Tpm2Error`], making them directly usable as clap
//! `value_parser` callbacks.

use std::path::PathBuf;

use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::{AesKeyBits, CamelliaKeyBits, Sm4KeyBits};
use tss_esapi::interface_types::reserved_handles::{Hierarchy, HierarchyAuth, Provision};
use tss_esapi::structures::{
    Auth, Data, HashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, SensitiveData,
    SignatureScheme, SymmetricDefinition,
};

use crate::error::Tpm2Error;
use crate::handle::ContextSource;

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Parse a hex `u32` value, accepting an optional `0x` prefix.
///
/// Intended for use as a clap `value_parser`:
/// ```ignore
/// #[arg(value_parser = crate::parse::parse_hex_u32)]
/// pub handle: u32,
/// ```
pub fn parse_hex_u32(s: &str) -> Result<u32, String> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(digits, 16)
        .map_err(|_| format!("expected a hex value (e.g. 0x01400001), got: '{s}'"))
}

// ---------------------------------------------------------------------------
// Duration
// ---------------------------------------------------------------------------

pub fn parse_duration(s: &str) -> Result<Option<std::time::Duration>, String> {
    let secs: u64 = s
        .parse()
        .map_err(|_| format!("expected a u64 value, got: '{s}'"))?;
    let duration = match secs {
        0 => None,
        _ => Some(std::time::Duration::from_secs(secs)),
    };
    Ok(duration)
}

// ---------------------------------------------------------------------------
// Context source
// ---------------------------------------------------------------------------

/// Parse a context source string into a [`ContextSource`].
///
/// Accepted formats:
/// - `file:<path>` — a JSON context file path
/// - `hex:<handle>` — a raw persistent TPM handle in hex (e.g. `hex:0x81010001`)
///
/// Intended for use as a clap `value_parser`:
/// ```ignore
/// #[arg(short = 'c', long, value_parser = parse_context_source)]
/// pub context: ContextSource,
/// ```
pub fn parse_context_source(s: &str) -> Result<ContextSource, String> {
    if let Some(path) = s.strip_prefix("file:") {
        Ok(ContextSource::File(PathBuf::from(path)))
    } else if let Some(hex_str) = s.strip_prefix("hex:") {
        let digits = hex_str
            .strip_prefix("0x")
            .or_else(|| hex_str.strip_prefix("0X"))
            .unwrap_or(hex_str);
        let handle = u32::from_str_radix(digits, 16)
            .map_err(|_| format!("invalid hex handle: '{hex_str}'"))?;
        Ok(ContextSource::Handle(handle))
    } else {
        Err(format!(
            "expected 'file:<path>' or 'hex:<handle>', got: '{s}'"
        ))
    }
}

// ---------------------------------------------------------------------------
// Hashing algorithm
// ---------------------------------------------------------------------------

/// Parse a hashing algorithm name.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_hashing_algorithm(s: &str) -> Result<HashingAlgorithm, String> {
    match s.to_lowercase().as_str() {
        "sha1" | "sha" => Ok(HashingAlgorithm::Sha1),
        "sha256" => Ok(HashingAlgorithm::Sha256),
        "sha384" => Ok(HashingAlgorithm::Sha384),
        "sha512" => Ok(HashingAlgorithm::Sha512),
        "sm3_256" | "sm3" => Ok(HashingAlgorithm::Sm3_256),
        "sha3_256" => Ok(HashingAlgorithm::Sha3_256),
        "sha3_384" => Ok(HashingAlgorithm::Sha3_384),
        "sha3_512" => Ok(HashingAlgorithm::Sha3_512),
        _ => Err(format!("unknown hashing algorithm: {s}")),
    }
}

// ---------------------------------------------------------------------------
// Signature scheme
// ---------------------------------------------------------------------------

/// Parse a signature scheme name together with the hashing algorithm it uses.
///
/// This function takes two parameters and therefore cannot be used as a clap
/// `value_parser` directly.  The `hash_alg` parameter should be parsed at CLI
/// time via [`parse_hashing_algorithm`], and this function should be called at
/// execution time to combine them.
pub fn parse_signature_scheme(
    s: &str,
    hash_alg: HashingAlgorithm,
) -> Result<SignatureScheme, String> {
    let hs = HashScheme::new(hash_alg);
    match s.to_lowercase().as_str() {
        "rsassa" => Ok(SignatureScheme::RsaSsa { scheme: hs }),
        "rsapss" => Ok(SignatureScheme::RsaPss { scheme: hs }),
        "ecdsa" => Ok(SignatureScheme::EcDsa { scheme: hs }),
        "sm2" => Ok(SignatureScheme::Sm2 { scheme: hs }),
        "ecschnorr" => Ok(SignatureScheme::EcSchnorr { scheme: hs }),
        "hmac" => Ok(SignatureScheme::Hmac { scheme: hs.into() }),
        "null" => Ok(SignatureScheme::Null),
        _ => Err(format!("unsupported signature scheme: {s}")),
    }
}

// ---------------------------------------------------------------------------
// Hierarchy / Provision / AuthHandle
// ---------------------------------------------------------------------------

/// Parse a hierarchy/auth-handle specification.
///
/// Accepted values:
/// - `o` / `owner`       → [`Hierarchy::Owner`]
/// - `p` / `platform`    → [`Hierarchy::Platform`]
/// - `e` / `endorsement` → [`Hierarchy::Endorsement`]
/// - `n` / `null`        → [`Hierarchy::Null`]
pub fn parse_hierarchy(value: &str) -> Result<Hierarchy, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(Hierarchy::Owner),
        "p" | "platform" => Ok(Hierarchy::Platform),
        "e" | "endorsement" => Ok(Hierarchy::Endorsement),
        "n" | "null" => Ok(Hierarchy::Null),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "unknown hierarchy: {value}"
        ))),
    }
}

/// Parse a provision handle (owner or platform) for administrative commands.
pub fn parse_provision(value: &str) -> Result<Provision, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(Provision::Owner),
        "p" | "platform" => Ok(Provision::Platform),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "provision must be 'o'/'owner' or 'p'/'platform', got: {value}"
        ))),
    }
}

/// Parse an auth handle from a string (for commands like `clear`).
pub fn parse_auth_handle(value: &str) -> Result<AuthHandle, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(AuthHandle::Owner),
        "p" | "platform" => Ok(AuthHandle::Platform),
        "l" | "lockout" => Ok(AuthHandle::Lockout),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "unknown auth handle: {value}"
        ))),
    }
}

/// Map a [`Provision`] to the corresponding [`HierarchyAuth`].
pub fn provision_to_hierarchy_auth(provision: Provision) -> HierarchyAuth {
    match provision {
        Provision::Owner => HierarchyAuth::Owner,
        Provision::Platform => HierarchyAuth::Platform,
    }
}

// ---------------------------------------------------------------------------
// Raw ESYS_TR hierarchy (for raw FFI commands)
// ---------------------------------------------------------------------------

/// Parse a hierarchy specification into a raw `ESYS_TR` handle.
///
/// Accepted values: `o`/`owner`, `p`/`platform`, `e`/`endorsement`,
/// `n`/`null`, `l`/`lockout`.
///
/// Intended for use as a clap `value_parser` in commands that call raw
/// ESYS FFI functions.
pub fn parse_esys_hierarchy(value: &str) -> Result<u32, Tpm2Error> {
    use tss_esapi::tss2_esys::*;
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(ESYS_TR_RH_OWNER),
        "p" | "platform" => Ok(ESYS_TR_RH_PLATFORM),
        "e" | "endorsement" => Ok(ESYS_TR_RH_ENDORSEMENT),
        "n" | "null" => Ok(ESYS_TR_RH_NULL),
        "l" | "lockout" => Ok(ESYS_TR_RH_LOCKOUT),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "unknown hierarchy: {value}"
        ))),
    }
}

/// Parse a hierarchy specification into a raw TPM2_RH handle constant.
pub fn parse_tpm2_rh_hierarchy(value: &str) -> Result<u32, Tpm2Error> {
    use tss_esapi::constants::tss::*;
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(TPM2_RH_OWNER),
        "p" | "platform" => Ok(TPM2_RH_PLATFORM),
        "e" | "endorsement" => Ok(TPM2_RH_ENDORSEMENT),
        "n" | "null" => Ok(TPM2_RH_NULL),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "unknown hierarchy: {value}"
        ))),
    }
}

/// NV authorization entity — either a hierarchy handle or "nv" (the index
/// authorizes itself).
#[derive(Debug, Clone, Copy)]
pub enum NvAuthEntity {
    /// Owner hierarchy
    Owner,
    /// Platform hierarchy
    Platform,
    /// The NV index itself is the auth entity
    NvIndex,
}

/// Parse an NV authorization entity.
///
/// Accepted values: `o`/`owner`, `p`/`platform`, or anything else
/// falls back to [`NvAuthEntity::NvIndex`].
pub fn parse_nv_auth_entity(value: &str) -> Result<NvAuthEntity, String> {
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(NvAuthEntity::Owner),
        "p" | "platform" => Ok(NvAuthEntity::Platform),
        _ => Ok(NvAuthEntity::NvIndex),
    }
}

// ---------------------------------------------------------------------------
// Authorization value
// ---------------------------------------------------------------------------

/// Parse an authorization value from a CLI string.
///
/// Supported formats:
/// - `hex:<hex_bytes>` — hex-encoded byte string
/// - `file:<path>`     — read raw bytes from file
/// - `<string>`        — plain UTF-8 password (fallback)
///
/// Intended for use as a clap `value_parser`.
pub fn parse_auth(value: &str) -> Result<Auth, Tpm2Error> {
    let bytes = if let Some(hex_str) = value.strip_prefix("hex:") {
        hex::decode(hex_str).map_err(|e| Tpm2Error::InvalidAuth(e.to_string()))?
    } else if let Some(path) = value.strip_prefix("file:") {
        std::fs::read(std::path::Path::new(path))?
    } else {
        value.as_bytes().to_vec()
    };
    Auth::try_from(bytes).map_err(|e| Tpm2Error::InvalidAuth(e.to_string()))
}

// ---------------------------------------------------------------------------
// NV attributes
// ---------------------------------------------------------------------------

/// Parse symbolic NV index attributes separated by `|`.
///
/// Supported attributes include standard flags (ownerwrite, ownerread, etc.)
/// and the NV index type via `nt=ordinary`, `nt=counter`, `nt=bits`,
/// `nt=extend`, `nt=pinfail`, `nt=pinpass`.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_nv_attributes(s: &str) -> Result<tss_esapi::attributes::NvIndexAttributes, String> {
    use tss_esapi::constants::NvIndexType;

    let mut builder = NvIndexAttributesBuilder::new();

    for attr in s.split('|') {
        let trimmed = attr.trim().to_lowercase();
        // Map NV types to TPM_NT constants (Bits 4-7 of TPMA_NV)
        if let Some(nt_val) = trimmed.strip_prefix("nt=") {
            let nv_type = match nt_val {
                "ordinary" | "0" => NvIndexType::Ordinary,
                "counter" | "1" => NvIndexType::Counter,
                "bits" | "2" => NvIndexType::Bits,
                "extend" | "4" => NvIndexType::Extend,
                "pinfail" | "8" => NvIndexType::PinFail,
                "pinpass" | "9" => NvIndexType::PinPass,
                _ => return Err(format!("unknown NV index type: {nt_val}")),
            };
            builder = builder.with_nv_index_type(nv_type);
            continue;
        }
        // Map NV attributes to TPMA_NV bits
        builder = match trimmed.as_str() {
            "ppwrite" | "pp_write" => builder.with_pp_write(true), // 0
            "ownerwrite" | "owner_write" => builder.with_owner_write(true), // 1
            "authwrite" | "auth_write" => builder.with_auth_write(true), // 2
            "policywrite" | "policy_write" => builder.with_policy_write(true), // 3
            "policydelete" | "policy_delete" => builder.with_policy_delete(true), // 10
            "writelocked" | "write_locked" => builder.with_write_locked(true), // 11
            "writeall" | "write_all" => builder.with_write_all(true), // 12
            "writedefine" | "write_define" => builder.with_write_define(true), // 13
            "write_stclear" => builder.with_write_stclear(true),   // 14
            "globallock" | "global_lock" => builder.with_global_lock(true), // 15
            "ppread" | "pp_read" => builder.with_pp_read(true),    // 16
            "ownerread" | "owner_read" => builder.with_owner_read(true), // 17
            "authread" | "auth_read" => builder.with_auth_read(true), // 18
            "policyread" | "policy_read" => builder.with_policy_read(true), // 19
            "noda" | "no_da" => builder.with_no_da(true),          // 25
            "orderly" => builder.with_orderly(true),               // 26
            "clear_stclear" => builder.with_clear_stclear(true),   // 27
            "readlocked" | "read_locked" => builder.with_read_locked(true), // 28
            "written" => builder.with_written(true),               // 29
            "platformcreate" | "platform_create" => builder.with_platform_create(true), // 30
            "read_stclear" => builder.with_read_stclear(true),     // 31
            // rust-tss-esapi v8.0.0-alpha.2 does not support the following fields:
            // 32: TPMA_EXTERNAL_NV_ENCRYPTION
            // 33: TPMA_EXTERNAL_NV_INTEGRITY
            // 34: TPMA_EXTERNAL_NV_ANTIROLLBACK
            _ => return Err(format!("unknown NV attribute: {attr}")),
        };
    }

    builder
        .build()
        .map_err(|e| format!("failed to build NV attributes: {e}"))
}

// ---------------------------------------------------------------------------
// PCR selection
// ---------------------------------------------------------------------------

/// Parse a PCR selection string like `sha256:0,1,2+sha1:all`.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_pcr_selection(spec: &str) -> Result<PcrSelectionList, String> {
    let mut builder = PcrSelectionListBuilder::new();

    for bank_spec in spec.split('+') {
        let (alg_str, indices_str) = bank_spec
            .split_once(':')
            .ok_or_else(|| format!("invalid PCR spec: missing ':' in '{bank_spec}'"))?;

        let alg = parse_hashing_algorithm(alg_str)?;
        let slots = parse_pcr_indices(indices_str)?;
        builder = builder.with_selection(alg, &slots);
    }

    builder
        .build()
        .map_err(|e| format!("failed to build PCR selection list: {e}"))
}

/// Build a default selection covering sha256 and sha1, all 24 PCRs.
pub fn default_pcr_selection() -> Result<PcrSelectionList, String> {
    let all_slots = all_pcr_slots();
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &all_slots)
        .with_selection(HashingAlgorithm::Sha1, &all_slots)
        .build()
        .map_err(|e| format!("failed to build default PCR selection list: {e}"))
}

/// Convert a PCR index (0..31) to the corresponding [`PcrSlot`] enum variant.
pub fn index_to_pcr_slot(idx: u8) -> Option<PcrSlot> {
    let bit: u32 = 1u32.checked_shl(idx as u32)?;
    PcrSlot::try_from(bit).ok()
}

/// Convert a [`PcrSlot`] back to its index (0..31).
pub fn pcr_slot_to_index(slot: PcrSlot) -> u8 {
    let val: u32 = slot.into();
    val.trailing_zeros() as u8
}

fn parse_pcr_indices(s: &str) -> Result<Vec<PcrSlot>, String> {
    if s.eq_ignore_ascii_case("all") {
        return Ok(all_pcr_slots());
    }

    s.split(',')
        .map(|tok| {
            let idx: u8 = tok
                .trim()
                .parse()
                .map_err(|_| format!("invalid PCR index: {tok}"))?;
            index_to_pcr_slot(idx).ok_or_else(|| format!("PCR index out of range: {idx}"))
        })
        .collect()
}

fn all_pcr_slots() -> Vec<PcrSlot> {
    (0u8..24).filter_map(index_to_pcr_slot).collect()
}

// ---------------------------------------------------------------------------
// Symmetric mode
// ---------------------------------------------------------------------------

/// Parse a symmetric cipher mode name.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_symmetric_mode(s: &str) -> Result<SymmetricMode, String> {
    match s.to_lowercase().as_str() {
        "cfb" => Ok(SymmetricMode::Cfb),
        "cbc" => Ok(SymmetricMode::Cbc),
        "ecb" => Ok(SymmetricMode::Ecb),
        "ofb" => Ok(SymmetricMode::Ofb),
        "ctr" => Ok(SymmetricMode::Ctr),
        "null" => Ok(SymmetricMode::Null),
        _ => Err(format!("unsupported symmetric mode: {s}")),
    }
}

// ---------------------------------------------------------------------------
// Qualification data
// ---------------------------------------------------------------------------

/// Parse qualification data from a CLI string.
///
/// Newtype wrapper around `Vec<u8>` so that clap does not interpret
/// `Option<Vec<u8>>` as a multi-value collection.
#[derive(Clone, Debug)]
pub struct Qualification(pub Vec<u8>);

impl Qualification {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Accepted formats:
/// - `hex:<hex_bytes>` — hex-encoded byte string (with optional 0x prefix)
/// - `file:<path>`     — read raw bytes from file
///
/// Intended for use as a clap `value_parser`.
pub fn parse_qualification(s: &str) -> Result<Qualification, String> {
    if let Some(hex_str) = s.strip_prefix("hex:") {
        let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        hex::decode(stripped)
            .map(Qualification)
            .map_err(|e| format!("invalid hex qualification data '{hex_str}': {e}"))
    } else if let Some(path) = s.strip_prefix("file:") {
        std::fs::read(std::path::Path::new(path))
            .map(Qualification)
            .map_err(|e| format!("reading qualification file '{path}': {e}"))
    } else {
        Err(format!(
            "expected 'hex:<hex_bytes>' or 'file:<path>', got: '{s}'"
        ))
    }
}

// ---------------------------------------------------------------------------
// ECC curve
// ---------------------------------------------------------------------------

/// Parse an ECC curve name.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_ecc_curve(s: &str) -> Result<EccCurve, String> {
    match s.to_lowercase().as_str() {
        "nistp192" | "ecc192" | "p192" => Ok(EccCurve::NistP192),
        "nistp224" | "ecc224" | "p224" => Ok(EccCurve::NistP224),
        "nistp256" | "ecc256" | "p256" => Ok(EccCurve::NistP256),
        "nistp384" | "ecc384" | "p384" => Ok(EccCurve::NistP384),
        "nistp521" | "ecc521" | "p521" => Ok(EccCurve::NistP521),
        "bnp256" => Ok(EccCurve::BnP256),
        "bnp638" => Ok(EccCurve::BnP638),
        "sm2p256" | "sm2" => Ok(EccCurve::Sm2P256),
        _ => Err(format!("unsupported ECC curve: {s}")),
    }
}

// ---------------------------------------------------------------------------
// Symmetric definition (for sessions)
// ---------------------------------------------------------------------------

/// Parse a symmetric algorithm definition.
///
/// Accepted formats:
/// - `aes-{128,192,256}-{cfb,cbc,ecb,ofb,ctr}` — AES with key size and mode
/// - `sm4-128-{cfb,cbc,ecb,ofb,ctr}` — SM4 with key size and mode
/// - `camellia-{128,192,256}-{cfb,cbc,ecb,ofb,ctr}` — Camellia with key size and mode
/// - `xor-{sha1,sha256,...}` — XOR with a hashing algorithm
/// - `null` — no symmetric algorithm
///
/// Legacy shorthand forms `aes128cfb` and `aes256cfb` are also accepted.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_symmetric_definition(s: &str) -> Result<SymmetricDefinition, String> {
    let lower = s.to_lowercase();

    // Handle "null" first.
    if lower == "null" {
        return Ok(SymmetricDefinition::Null);
    }

    // Legacy shorthand aliases for backwards compatibility.
    match lower.as_str() {
        "aes128cfb" => {
            return Ok(SymmetricDefinition::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            });
        }
        "aes256cfb" => {
            return Ok(SymmetricDefinition::Aes {
                key_bits: AesKeyBits::Aes256,
                mode: SymmetricMode::Cfb,
            });
        }
        "xor" => {
            return Ok(SymmetricDefinition::Xor {
                hashing_algorithm: HashingAlgorithm::Sha256,
            });
        }
        _ => {}
    }

    let parts: Vec<&str> = lower.split('-').collect();

    match parts[0] {
        "aes" => {
            if parts.len() != 3 {
                return Err(format!(
                    "expected 'aes-<bits>-<mode>' (e.g. aes-128-cfb), got: '{s}'"
                ));
            }
            let key_bits = match parts[1] {
                "128" => AesKeyBits::Aes128,
                "192" => AesKeyBits::Aes192,
                "256" => AesKeyBits::Aes256,
                _ => {
                    return Err(format!(
                        "unsupported AES key size: {} (expected 128, 192, or 256)",
                        parts[1]
                    ));
                }
            };
            let mode = parse_symmetric_mode(parts[2])?;
            if mode == SymmetricMode::Null {
                return Err(format!("unsupported AES symmetric mode: {}", parts[2]));
            };
            Ok(SymmetricDefinition::Aes { key_bits, mode })
        }
        "sm4" => {
            if parts.len() != 3 {
                return Err(format!(
                    "expected 'sm4-128-<mode>' (e.g. sm4-128-cfb), got: '{s}'"
                ));
            }
            let key_bits = match parts[1] {
                "128" => Sm4KeyBits::Sm4_128,
                _ => {
                    return Err(format!(
                        "unsupported SM4 key size: {} (expected 128)",
                        parts[1]
                    ));
                }
            };
            let mode = parse_symmetric_mode(parts[2])?;
            if mode == SymmetricMode::Null {
                return Err(format!("unsupported SM4 symmetric mode: {}", parts[2]));
            };
            Ok(SymmetricDefinition::Sm4 { key_bits, mode })
        }
        "camellia" => {
            if parts.len() != 3 {
                return Err(format!(
                    "expected 'camellia-<bits>-<mode>' (e.g. camellia-128-cfb), got: '{s}'"
                ));
            }
            let key_bits = match parts[1] {
                "128" => CamelliaKeyBits::Camellia128,
                "192" => CamelliaKeyBits::Camellia192,
                "256" => CamelliaKeyBits::Camellia256,
                _ => {
                    return Err(format!(
                        "unsupported Camellia key size: {} (expected 128, 192, or 256)",
                        parts[1]
                    ));
                }
            };
            let mode = parse_symmetric_mode(parts[2])?;
            if mode == SymmetricMode::Null {
                return Err(format!("unsupported Camellia symmetric mode: {}", parts[2]));
            };
            Ok(SymmetricDefinition::Camellia { key_bits, mode })
        }
        "xor" => {
            if parts.len() != 2 {
                return Err(format!(
                    "expected 'xor-<hash>' (e.g. xor-sha256), got: '{s}'"
                ));
            }
            let hashing_algorithm = parse_hashing_algorithm(parts[1])?;
            Ok(SymmetricDefinition::Xor { hashing_algorithm })
        }
        _ => Err(format!(
            "unsupported symmetric algorithm: '{}'; expected aes, sm4, camellia, xor, or null",
            parts[0]
        )),
    }
}

// ---------------------------------------------------------------------------
// Sensitive data (outside info, etc.)
// ---------------------------------------------------------------------------

/// Parse raw bytes from a CLI string.
///
/// Supported formats:
/// - `hex:<hex_bytes>` — hex-encoded byte string
/// - `file:<path>`     — read raw bytes from file
/// - `<string>`        — plain UTF-8 string (fallback)
///
/// Intended for use as a clap `value_parser`.
pub fn parse_bytes(value: &str) -> Result<Vec<u8>, String> {
    if let Some(hex_str) = value.strip_prefix("hex:") {
        hex::decode(hex_str).map_err(|e| format!("invalid hex data: {e}"))
    } else if let Some(path) = value.strip_prefix("file:") {
        std::fs::read(std::path::Path::new(path))
            .map_err(|e| format!("reading data from '{path}': {e}"))
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

/// Parse sensitive data from a CLI string.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_sensitive_data(value: &str) -> Result<SensitiveData, String> {
    let bytes = parse_bytes(value)?;
    SensitiveData::try_from(bytes).map_err(|e| format!("data too large: {e}"))
}

/// Parse a Data buffer from a CLI string (for outside_info etc.).
///
/// Intended for use as a clap `value_parser`.
pub fn parse_data(value: &str) -> Result<Data, String> {
    let bytes = parse_bytes(value)?;
    Data::try_from(bytes).map_err(|e| format!("data too large: {e}"))
}

// ---------------------------------------------------------------------------
// TPM2 comparison operation
// ---------------------------------------------------------------------------

/// Parse a TPM2_EO_* comparison operation name to its `u16` constant.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_tpm2_operation(s: &str) -> Result<u16, String> {
    use tss_esapi::constants::tss::*;
    match s.to_lowercase().as_str() {
        "eq" => Ok(TPM2_EO_EQ),
        "neq" => Ok(TPM2_EO_NEQ),
        "sgt" => Ok(TPM2_EO_SIGNED_GT),
        "ugt" => Ok(TPM2_EO_UNSIGNED_GT),
        "slt" => Ok(TPM2_EO_SIGNED_LT),
        "ult" => Ok(TPM2_EO_UNSIGNED_LT),
        "sge" => Ok(TPM2_EO_SIGNED_GE),
        "uge" => Ok(TPM2_EO_UNSIGNED_GE),
        "sle" => Ok(TPM2_EO_SIGNED_LE),
        "ule" => Ok(TPM2_EO_UNSIGNED_LE),
        "bs" => Ok(TPM2_EO_BITSET),
        "bc" => Ok(TPM2_EO_BITCLEAR),
        _ => Err(format!(
            "unknown operation: {s}; expected eq/neq/sgt/ugt/slt/ult/sge/uge/sle/ule/bs/bc"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symdef_aes_256_cbc() {
        let def = parse_symmetric_definition("aes-256-cbc").unwrap();
        assert_eq!(
            def,
            SymmetricDefinition::Aes {
                key_bits: AesKeyBits::Aes256,
                mode: SymmetricMode::Cbc,
            }
        );
    }

    #[test]
    fn symdef_camellia_192_ecb() {
        let def = parse_symmetric_definition("camellia-192-ecb").unwrap();
        assert_eq!(
            def,
            SymmetricDefinition::Camellia {
                key_bits: CamelliaKeyBits::Camellia192,
                mode: SymmetricMode::Ecb,
            }
        );
    }

    #[test]
    fn symdef_xor_sha1() {
        let def = parse_symmetric_definition("xor-sha1").unwrap();
        assert_eq!(
            def,
            SymmetricDefinition::Xor {
                hashing_algorithm: HashingAlgorithm::Sha1,
            }
        );
    }

    // Legacy shorthand forms
    #[test]
    fn symdef_aes128cfb() {
        let def = parse_symmetric_definition("aes128cfb").unwrap();
        assert_eq!(def, SymmetricDefinition::AES_128_CFB);
    }

    #[test]
    fn symdef_aes256cfb() {
        let def = parse_symmetric_definition("aes256cfb").unwrap();
        assert_eq!(def, SymmetricDefinition::AES_256_CFB);
    }

    #[test]
    fn symdef_xor() {
        let def = parse_symmetric_definition("xor").unwrap();
        assert_eq!(
            def,
            SymmetricDefinition::Xor {
                hashing_algorithm: HashingAlgorithm::Sha256,
            }
        );
    }

    // Error cases
    #[test]
    fn symdef_unknown_algo() {
        assert!(parse_symmetric_definition("foobar-128-cfb").is_err());
    }

    #[test]
    fn symdef_aes_128_with_invalid_null_mode() {
        assert!(parse_symmetric_definition("aes-128-null").is_err());
    }

    #[test]
    fn symdef_sm4_cbc_with_unavailable_192_bits() {
        assert!(parse_symmetric_definition("sm4-192-cbc").is_err());
    }

    #[test]
    fn symdef_empty_string() {
        assert!(parse_symmetric_definition("").is_err());
    }
}
