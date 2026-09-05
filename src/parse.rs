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

use std::fmt;
use std::path::PathBuf;

use tss_esapi::attributes::{LocalityAttributes, NvIndexAttributesBuilder};
use tss_esapi::constants::{ClockAdjust, CommandCode};
use tss_esapi::handles::{AuthHandle, NvIndexTpmHandle, PcrHandle, PersistentTpmHandle};
use tss_esapi::interface_types::ArithmeticComparison;
use tss_esapi::interface_types::algorithm::{
    EccKeyExchangeAlgorithm, HashingAlgorithm, SymmetricMode,
};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::{AesKeyBits, CamelliaKeyBits, RsaKeyBits, Sm4KeyBits};
use tss_esapi::interface_types::reserved_handles::{Enables, Hierarchy, HierarchyAuth, Provision};
use tss_esapi::structures::{
    Auth, CommandCodeList, Data, Digest, DigestValues, HashScheme, Name, Nonce, PcrSelectSize,
    PcrSelectionList, PcrSelectionListBuilder, PcrSlot, PublicKeyedHashParameters,
    PublicParameters, PublicRsaParameters, RsaDecryptionScheme, RsaExponent, RsaScheme,
    SensitiveData, SignatureScheme, SymmetricCipherParameters, SymmetricDefinition,
    SymmetricDefinitionObject, Timeout,
};

use crate::error::Tpm2Error;
use crate::handle::ContextSource;
use crate::tcti::TctiConfig;

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

/// Parse a hex `u64` value, accepting an optional `0x` prefix.
pub fn parse_hex_u64(s: &str) -> Result<u64, String> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(digits, 16)
        .map_err(|_| format!("expected a hex value (e.g. 0x01), got: '{s}'"))
}

/// Parse and validate an NV index TPM handle.
pub fn parse_nv_index(s: &str) -> Result<NvIndexTpmHandle, String> {
    let handle = parse_hex_u32(s)?;
    NvIndexTpmHandle::new(handle)
        .map_err(|e| format!("invalid NV index handle 0x{handle:08x}: {e}"))
}

/// Parse and validate a persistent object TPM handle.
pub fn parse_persistent_handle(s: &str) -> Result<PersistentTpmHandle, String> {
    let handle = parse_hex_u32(s)?;
    PersistentTpmHandle::new(handle)
        .map_err(|e| format!("invalid persistent handle 0x{handle:08x}: {e}"))
}

/// Parse and validate a TPM handle.
pub fn parse_tpm_handle(s: &str) -> Result<tss_esapi::handles::TpmHandle, String> {
    let handle = parse_hex_u32(s)?;
    tss_esapi::handles::TpmHandle::try_from(handle)
        .map_err(|e| format!("invalid TPM handle 0x{handle:08x}: {e}"))
}

/// Parse an RSA key size supported by the TPM public-area type.
pub fn parse_rsa_key_bits(s: &str) -> Result<RsaKeyBits, String> {
    match s {
        "1024" => Ok(RsaKeyBits::Rsa1024),
        "2048" => Ok(RsaKeyBits::Rsa2048),
        "3072" => Ok(RsaKeyBits::Rsa3072),
        "4096" => Ok(RsaKeyBits::Rsa4096),
        _ => Err(format!(
            "unsupported RSA key size: {s}; use 1024, 2048, 3072, or 4096"
        )),
    }
}

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

pub fn parse_tcti_config(s: &str) -> Result<TctiConfig, Tpm2Error> {
    s.parse()
}

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
        let handle = tss_esapi::handles::TpmHandle::try_from(handle)
            .map_err(|e| format!("invalid TPM handle 0x{handle:08x}: {e}"))?;
        Ok(ContextSource::Handle(handle))
    } else {
        Err(format!(
            "expected 'file:<path>' or 'hex:<handle>', got: '{s}'"
        ))
    }
}

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

/// Parse a TPM clock-rate adjustment.
pub fn parse_clock_adjust(s: &str) -> Result<ClockAdjust, String> {
    match s.to_ascii_lowercase().as_str() {
        "slower" => Ok(ClockAdjust::CoarseSlower),
        "slow" => Ok(ClockAdjust::FineSlower),
        "medium" | "none" => Ok(ClockAdjust::NoChange),
        "fast" => Ok(ClockAdjust::FineFaster),
        "faster" => Ok(ClockAdjust::CoarseFaster),
        _ => Err(format!(
            "invalid rate: {s}; expected slower/slow/medium/fast/faster"
        )),
    }
}

/// The hash-independent part of a TPM signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSchemeKind {
    RsaSsa,
    RsaPss,
    EcDsa,
    Sm2,
    EcSchnorr,
    Hmac,
    Null,
}

impl SignatureSchemeKind {
    /// Combine a parsed scheme kind with its separately parsed hash algorithm.
    pub fn with_hash(self, hash_alg: HashingAlgorithm) -> SignatureScheme {
        let hs = HashScheme::new(hash_alg);
        match self {
            Self::RsaSsa => SignatureScheme::RsaSsa { scheme: hs },
            Self::RsaPss => SignatureScheme::RsaPss { scheme: hs },
            Self::EcDsa => SignatureScheme::EcDsa { scheme: hs },
            Self::Sm2 => SignatureScheme::Sm2 { scheme: hs },
            Self::EcSchnorr => SignatureScheme::EcSchnorr { scheme: hs },
            Self::Hmac => SignatureScheme::Hmac { scheme: hs.into() },
            Self::Null => SignatureScheme::Null,
        }
    }
}

/// Parse the hash-independent part of a signature scheme.
pub fn parse_signature_scheme_kind(s: &str) -> Result<SignatureSchemeKind, String> {
    match s.to_ascii_lowercase().as_str() {
        "rsassa" => Ok(SignatureSchemeKind::RsaSsa),
        "rsapss" => Ok(SignatureSchemeKind::RsaPss),
        "ecdsa" => Ok(SignatureSchemeKind::EcDsa),
        "sm2" => Ok(SignatureSchemeKind::Sm2),
        "ecschnorr" => Ok(SignatureSchemeKind::EcSchnorr),
        "hmac" => Ok(SignatureSchemeKind::Hmac),
        "null" => Ok(SignatureSchemeKind::Null),
        _ => Err(format!("unsupported signature scheme: {s}")),
    }
}

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
        "e" | "endorsement" => Ok(AuthHandle::Endorsement),
        "l" | "lockout" => Ok(AuthHandle::Lockout),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "unknown auth handle: {value}"
        ))),
    }
}

/// Parse an authorization handle restricted to owner or platform.
pub fn parse_owner_or_platform_auth_handle(value: &str) -> Result<AuthHandle, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(AuthHandle::Owner),
        "p" | "platform" => Ok(AuthHandle::Platform),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "authorization handle must be owner or platform, got: {value}"
        ))),
    }
}

/// Parse an authorization handle restricted to platform or lockout.
pub fn parse_platform_or_lockout_auth_handle(value: &str) -> Result<AuthHandle, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "p" | "platform" => Ok(AuthHandle::Platform),
        "l" | "lockout" => Ok(AuthHandle::Lockout),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "authorization handle must be platform or lockout, got: {value}"
        ))),
    }
}

/// Parse an authorization handle restricted to endorsement or platform.
pub fn parse_endorsement_or_platform_auth_handle(value: &str) -> Result<AuthHandle, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "e" | "endorsement" => Ok(AuthHandle::Endorsement),
        "p" | "platform" => Ok(AuthHandle::Platform),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "authorization handle must be endorsement or platform, got: {value}"
        ))),
    }
}

/// Parse a hierarchy authorization handle.
pub fn parse_hierarchy_auth(value: &str) -> Result<HierarchyAuth, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(HierarchyAuth::Owner),
        "p" | "platform" => Ok(HierarchyAuth::Platform),
        "e" | "endorsement" => Ok(HierarchyAuth::Endorsement),
        "l" | "lockout" => Ok(HierarchyAuth::Lockout),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "unknown hierarchy authorization handle: {value}"
        ))),
    }
}

/// Parse a hierarchy selector for TPM2_HierarchyControl.
pub fn parse_enables(value: &str) -> Result<Enables, Tpm2Error> {
    match value.to_lowercase().as_str() {
        "o" | "owner" => Ok(Enables::Owner),
        "p" | "platform" => Ok(Enables::Platform),
        "e" | "endorsement" => Ok(Enables::Endorsement),
        "n" | "null" => Ok(Enables::Null),
        "pn" | "platform-nv" | "platform_nv" => Ok(Enables::PlatformNv),
        _ => Err(Tpm2Error::InvalidHandle(format!(
            "unknown hierarchy selector: {value}"
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
/// Accepted values: `o`/`owner`, `p`/`platform`, or `nv`/`index`.
pub fn parse_nv_auth_entity(value: &str) -> Result<NvAuthEntity, String> {
    match value.to_ascii_lowercase().as_str() {
        "o" | "owner" => Ok(NvAuthEntity::Owner),
        "p" | "platform" => Ok(NvAuthEntity::Platform),
        "nv" | "index" => Ok(NvAuthEntity::NvIndex),
        _ => Err(format!(
            "unknown NV authorization entity: {value}; expected owner/platform/nv"
        )),
    }
}

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

/// Authorization for an EK credential key: either an external policy session
/// or an endorsement-hierarchy authorization value.
#[derive(Debug, Clone)]
pub enum CredentialKeyAuth {
    Session(PathBuf),
    Auth(Auth),
}

pub fn parse_credential_key_auth(value: &str) -> Result<CredentialKeyAuth, Tpm2Error> {
    if let Some(path) = value.strip_prefix("session:") {
        if path.is_empty() {
            return Err(Tpm2Error::InvalidAuth(
                "session path must not be empty".to_owned(),
            ));
        }
        Ok(CredentialKeyAuth::Session(PathBuf::from(path)))
    } else {
        parse_auth(value).map(CredentialKeyAuth::Auth)
    }
}

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
            _ => return Err(format!("unknown NV attribute: {attr}")),
        };
    }

    builder
        .build()
        .map_err(|e| format!("failed to build NV attributes: {e}"))
}

/// Asymmetric key algorithm accepted by EK/AK/primary-key commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsymmetricAlgorithm {
    Rsa,
    Ecc,
}

impl AsymmetricAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rsa => "rsa",
            Self::Ecc => "ecc",
        }
    }
}

impl fmt::Display for AsymmetricAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn parse_asymmetric_algorithm(s: &str) -> Result<AsymmetricAlgorithm, String> {
    match s.to_ascii_lowercase().as_str() {
        "rsa" => Ok(AsymmetricAlgorithm::Rsa),
        "ecc" => Ok(AsymmetricAlgorithm::Ecc),
        _ => Err(format!(
            "unsupported asymmetric algorithm: {s}; expected rsa/ecc"
        )),
    }
}

/// Child-object algorithms accepted by `create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateAlgorithm {
    Rsa,
    Ecc,
    Hmac,
    KeyedHash,
}

pub fn parse_create_algorithm(s: &str) -> Result<CreateAlgorithm, String> {
    match s.to_ascii_lowercase().as_str() {
        "rsa" => Ok(CreateAlgorithm::Rsa),
        "ecc" => Ok(CreateAlgorithm::Ecc),
        "hmac" => Ok(CreateAlgorithm::Hmac),
        "keyedhash" => Ok(CreateAlgorithm::KeyedHash),
        _ => Err(format!(
            "unsupported key algorithm: {s}; expected rsa/ecc/hmac/keyedhash"
        )),
    }
}

/// Hash-independent RSA encryption/decryption scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaDecryptionSchemeKind {
    RsaEs,
    Oaep,
    Null,
}

impl RsaDecryptionSchemeKind {
    pub fn with_hash(self, hash_alg: HashingAlgorithm) -> RsaDecryptionScheme {
        match self {
            Self::RsaEs => RsaDecryptionScheme::RsaEs,
            Self::Oaep => RsaDecryptionScheme::Oaep(HashScheme::new(hash_alg)),
            Self::Null => RsaDecryptionScheme::Null,
        }
    }
}

pub fn parse_rsa_decryption_scheme_kind(s: &str) -> Result<RsaDecryptionSchemeKind, String> {
    match s.to_ascii_lowercase().as_str() {
        "rsaes" => Ok(RsaDecryptionSchemeKind::RsaEs),
        "oaep" => Ok(RsaDecryptionSchemeKind::Oaep),
        "null" => Ok(RsaDecryptionSchemeKind::Null),
        _ => Err(format!(
            "unsupported RSA scheme: {s}; expected rsaes/oaep/null"
        )),
    }
}

/// Parse the inner-wrapper algorithm used by Duplicate and Import.
pub fn parse_wrapper_algorithm(s: &str) -> Result<SymmetricDefinitionObject, String> {
    match s.to_ascii_lowercase().as_str() {
        "null" => Ok(SymmetricDefinitionObject::Null),
        "aes128cfb" | "aes" => Ok(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: SymmetricMode::Cfb,
        }),
        "aes256cfb" => Ok(SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes256,
            mode: SymmetricMode::Cfb,
        }),
        _ => Err(format!(
            "unsupported wrapper algorithm: {s}; expected null/aes128cfb/aes256cfb"
        )),
    }
}

/// Parse an ECC two-phase key-exchange scheme.
pub fn parse_ecc_key_exchange_algorithm(s: &str) -> Result<EccKeyExchangeAlgorithm, String> {
    match s.to_ascii_lowercase().as_str() {
        "ecdh" => Ok(EccKeyExchangeAlgorithm::EcDh),
        "sm2" => Ok(EccKeyExchangeAlgorithm::Sm2),
        _ => Err(format!(
            "unsupported key exchange scheme: {s}; expected ecdh/sm2"
        )),
    }
}

/// Capability query names accepted by `getcap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityQuery {
    Algorithms,
    Commands,
    Pcrs,
    PropertiesFixed,
    PropertiesVariable,
    EccCurves,
    HandlesTransient,
    HandlesPersistent,
    HandlesPermanent,
    HandlesPcr,
    HandlesNvIndex,
    HandlesLoadedSession,
    HandlesSavedSession,
}

pub fn parse_capability_query(s: &str) -> Result<CapabilityQuery, String> {
    match s.to_ascii_lowercase().as_str() {
        "algorithms" => Ok(CapabilityQuery::Algorithms),
        "commands" => Ok(CapabilityQuery::Commands),
        "pcrs" => Ok(CapabilityQuery::Pcrs),
        "properties-fixed" => Ok(CapabilityQuery::PropertiesFixed),
        "properties-variable" => Ok(CapabilityQuery::PropertiesVariable),
        "ecc-curves" => Ok(CapabilityQuery::EccCurves),
        "handles-transient" => Ok(CapabilityQuery::HandlesTransient),
        "handles-persistent" => Ok(CapabilityQuery::HandlesPersistent),
        "handles-permanent" => Ok(CapabilityQuery::HandlesPermanent),
        "handles-pcr" => Ok(CapabilityQuery::HandlesPcr),
        "handles-nv-index" => Ok(CapabilityQuery::HandlesNvIndex),
        "handles-loaded-session" => Ok(CapabilityQuery::HandlesLoadedSession),
        "handles-saved-session" => Ok(CapabilityQuery::HandlesSavedSession),
        _ => Err(format!(
            "unknown capability '{s}'; use -l to list supported capabilities"
        )),
    }
}

/// Structure formats accepted by `print`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintStructureType {
    Attest,
    Context,
    PublicBuffer,
    Public,
}

pub fn parse_print_structure_type(s: &str) -> Result<PrintStructureType, String> {
    match s.to_ascii_lowercase().as_str() {
        "tpms_attest" => Ok(PrintStructureType::Attest),
        "tpms_context" => Ok(PrintStructureType::Context),
        "tpm2b_public" => Ok(PrintStructureType::PublicBuffer),
        "tpmt_public" => Ok(PrintStructureType::Public),
        _ => Err(format!(
            "unsupported type: {s}; expected TPMS_ATTEST/TPMS_CONTEXT/TPM2B_PUBLIC/TPMT_PUBLIC"
        )),
    }
}

/// Raw TPM algorithm identifiers for IncrementalSelfTest.
#[derive(Debug, Clone)]
pub struct AlgorithmIdentifierList(Vec<u16>);

impl AlgorithmIdentifierList {
    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }
}

pub fn parse_algorithm_identifier_list(s: &str) -> Result<AlgorithmIdentifierList, String> {
    use tss_esapi::constants::tss::*;
    use tss_esapi::tss2_esys::TPML_ALG;

    let algorithms = s
        .split(',')
        .map(|alg| match alg.trim().to_ascii_lowercase().as_str() {
            "sha1" | "sha" => Ok(TPM2_ALG_SHA1),
            "sha256" => Ok(TPM2_ALG_SHA256),
            "sha384" => Ok(TPM2_ALG_SHA384),
            "sha512" => Ok(TPM2_ALG_SHA512),
            "rsa" => Ok(TPM2_ALG_RSA),
            "ecc" => Ok(TPM2_ALG_ECC),
            "aes" => Ok(TPM2_ALG_AES),
            "hmac" => Ok(TPM2_ALG_HMAC),
            _ => Err(format!("unknown algorithm: {alg}")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let maximum = TPML_ALG::default().algorithms.len();
    if algorithms.len() > maximum {
        return Err(format!(
            "too many algorithms: {}; maximum is {maximum}",
            algorithms.len()
        ));
    }
    Ok(AlgorithmIdentifierList(algorithms))
}

/// Build the exact public-parameter set accepted by `testparms`.
pub fn parse_public_parameters(s: &str) -> Result<PublicParameters, String> {
    match s.to_ascii_lowercase().as_str() {
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
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            },
        ))),
        "aes192" => Ok(PublicParameters::SymCipher(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes192,
                mode: SymmetricMode::Cfb,
            },
        ))),
        "aes256" => Ok(PublicParameters::SymCipher(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes256,
                mode: SymmetricMode::Cfb,
            },
        ))),
        _ => Err(format!("unsupported parameter set: {s}")),
    }
}

/// Parse a PCR index in the range supported by TPM 2.0 PCR handles.
pub fn parse_pcr_handle(s: &str) -> Result<PcrHandle, String> {
    let index = s
        .parse::<u8>()
        .map_err(|_| format!("invalid PCR index: {s}"))?;

    match index {
        0 => Ok(PcrHandle::Pcr0),
        1 => Ok(PcrHandle::Pcr1),
        2 => Ok(PcrHandle::Pcr2),
        3 => Ok(PcrHandle::Pcr3),
        4 => Ok(PcrHandle::Pcr4),
        5 => Ok(PcrHandle::Pcr5),
        6 => Ok(PcrHandle::Pcr6),
        7 => Ok(PcrHandle::Pcr7),
        8 => Ok(PcrHandle::Pcr8),
        9 => Ok(PcrHandle::Pcr9),
        10 => Ok(PcrHandle::Pcr10),
        11 => Ok(PcrHandle::Pcr11),
        12 => Ok(PcrHandle::Pcr12),
        13 => Ok(PcrHandle::Pcr13),
        14 => Ok(PcrHandle::Pcr14),
        15 => Ok(PcrHandle::Pcr15),
        16 => Ok(PcrHandle::Pcr16),
        17 => Ok(PcrHandle::Pcr17),
        18 => Ok(PcrHandle::Pcr18),
        19 => Ok(PcrHandle::Pcr19),
        20 => Ok(PcrHandle::Pcr20),
        21 => Ok(PcrHandle::Pcr21),
        22 => Ok(PcrHandle::Pcr22),
        23 => Ok(PcrHandle::Pcr23),
        24 => Ok(PcrHandle::Pcr24),
        25 => Ok(PcrHandle::Pcr25),
        26 => Ok(PcrHandle::Pcr26),
        27 => Ok(PcrHandle::Pcr27),
        28 => Ok(PcrHandle::Pcr28),
        29 => Ok(PcrHandle::Pcr29),
        30 => Ok(PcrHandle::Pcr30),
        31 => Ok(PcrHandle::Pcr31),
        _ => Err(format!("PCR index out of range: {index}")),
    }
}

/// Parse a PCR selection string like `sha256:0,1,2+sha1:all`.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_pcr_selection(spec: &str) -> Result<PcrSelectionList, String> {
    let mut builder = PcrSelectionListBuilder::new();
    let mut needs_four_octets = false;

    for bank_spec in spec.split('+') {
        let (alg_str, indices_str) = bank_spec
            .split_once(':')
            .ok_or_else(|| format!("invalid PCR spec: missing ':' in '{bank_spec}'"))?;

        let alg = parse_hashing_algorithm(alg_str)?;
        let slots = parse_pcr_indices(indices_str)?;
        needs_four_octets |= slots.iter().any(|slot| pcr_slot_to_index(*slot) >= 24);
        builder = builder.with_selection(alg, &slots);
    }

    if needs_four_octets {
        builder = builder.with_size_of_select(PcrSelectSize::FourOctets);
    }

    builder
        .build()
        .map_err(|e| format!("failed to build PCR selection list: {e}"))
}

/// Parse a PCR allocation string like `sha256:0,1,2+sha1:all`.
pub fn parse_pcr_allocation(spec: &str) -> Result<PcrSelectionList, String> {
    let mut builder = PcrSelectionListBuilder::new();
    let mut needs_four_octets = false;

    for bank_spec in spec.split('+') {
        let (algorithm, indices) = bank_spec
            .split_once(':')
            .ok_or_else(|| format!("invalid PCR spec: missing ':' in '{bank_spec}'"))?;
        let algorithm = parse_hashing_algorithm(algorithm)?;
        let slots = if indices.eq_ignore_ascii_case("all") {
            all_pcr_slots()
        } else {
            indices
                .split(',')
                .map(|index| {
                    let index = index
                        .trim()
                        .parse::<u8>()
                        .map_err(|_| format!("invalid PCR index: {index}"))?;
                    if index >= 32 {
                        return Err(format!("PCR index out of range: {index}"));
                    }
                    index_to_pcr_slot(index)
                        .ok_or_else(|| format!("PCR index out of range: {index}"))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        needs_four_octets |= slots.iter().any(|slot| pcr_slot_to_index(*slot) >= 24);
        builder = builder.with_selection(algorithm, &slots);
    }

    if needs_four_octets {
        builder = builder.with_size_of_select(PcrSelectSize::FourOctets);
    }

    builder
        .build()
        .map_err(|e| format!("failed to build PCR allocation: {e}"))
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

/// Parse a literal UTF-8 CLI string into a TPM `Data` buffer.
pub fn parse_utf8_data(value: &str) -> Result<Data, String> {
    Data::try_from(value.as_bytes().to_vec()).map_err(|e| format!("data too large: {e}"))
}

/// Parse a TPM comparison operation name.
///
/// Intended for use as a clap `value_parser`.
pub fn parse_tpm2_operation(s: &str) -> Result<ArithmeticComparison, String> {
    match s.to_lowercase().as_str() {
        "eq" => Ok(ArithmeticComparison::Eq),
        "neq" => Ok(ArithmeticComparison::Neq),
        "sgt" => Ok(ArithmeticComparison::SignedGt),
        "ugt" => Ok(ArithmeticComparison::UnsignedGt),
        "slt" => Ok(ArithmeticComparison::SignedLt),
        "ult" => Ok(ArithmeticComparison::UnsignedLt),
        "sge" => Ok(ArithmeticComparison::SignedGe),
        "uge" => Ok(ArithmeticComparison::UnsignedGe),
        "sle" => Ok(ArithmeticComparison::SignedLe),
        "ule" => Ok(ArithmeticComparison::UnsignedLe),
        "bs" => Ok(ArithmeticComparison::BitSet),
        "bc" => Ok(ArithmeticComparison::BitClear),
        _ => Err(format!(
            "unknown operation: {s}; expected eq/neq/sgt/ugt/slt/ult/sge/uge/sle/ule/bs/bc"
        )),
    }
}

fn decode_hex_argument(s: &str, description: &str) -> Result<Vec<u8>, String> {
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(digits).map_err(|e| format!("invalid {description} hex: {e}"))
}

pub fn parse_hex_digest(s: &str) -> Result<Digest, String> {
    Digest::try_from(decode_hex_argument(s, "digest")?).map_err(|e| format!("invalid digest: {e}"))
}

pub fn parse_hex_nonce(s: &str) -> Result<Nonce, String> {
    Nonce::try_from(decode_hex_argument(s, "nonce")?).map_err(|e| format!("invalid nonce: {e}"))
}

pub fn parse_hex_timeout(s: &str) -> Result<Timeout, String> {
    Timeout::try_from(decode_hex_argument(s, "timeout")?)
        .map_err(|e| format!("invalid timeout: {e}"))
}

pub fn parse_hex_name(s: &str) -> Result<Name, String> {
    Name::try_from(decode_hex_argument(s, "name")?).map_err(|e| format!("invalid name: {e}"))
}

/// Parse a command code from its hexadecimal value or a commonly used name.
pub fn parse_command_code(s: &str) -> Result<CommandCode, String> {
    use tss_esapi::constants::tss::*;

    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if let Ok(raw) = u32::from_str_radix(digits, 16) {
        return CommandCode::try_from(raw)
            .map_err(|e| format!("invalid command code 0x{raw:08x}: {e}"));
    }

    let raw = match s.to_ascii_lowercase().as_str() {
        "unseal" => TPM2_CC_Unseal,
        "sign" => TPM2_CC_Sign,
        "nv_read" | "nvread" => TPM2_CC_NV_Read,
        "nv_write" | "nvwrite" => TPM2_CC_NV_Write,
        "duplicate" => TPM2_CC_Duplicate,
        "certify" => TPM2_CC_Certify,
        "quote" => TPM2_CC_Quote,
        "create" => TPM2_CC_Create,
        _ => return Err(format!("unknown command code: {s}")),
    };
    CommandCode::try_from(raw).map_err(|e| format!("invalid command code: {e}"))
}

pub fn parse_command_code_list(s: &str) -> Result<CommandCodeList, String> {
    let command_codes = s
        .split(',')
        .map(|code| parse_command_code(code.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    CommandCodeList::try_from(command_codes).map_err(|e| format!("invalid command code list: {e}"))
}

/// Parse a locality number (decimal) or locality bit mask (`0x`-prefixed hex).
pub fn parse_locality(s: &str) -> Result<LocalityAttributes, String> {
    let value = if let Some(digits) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(digits, 16).map_err(|_| format!("invalid locality: {s}"))?
    } else {
        s.parse::<u8>()
            .map_err(|_| format!("invalid locality: {s}"))?
    };
    Ok(LocalityAttributes(value))
}

/// A fully parsed PCR extend argument.
#[derive(Debug, Clone)]
pub struct PcrExtendArgument {
    pcr_index: u8,
    pcr_handle: PcrHandle,
    digest_values: DigestValues,
}

impl PcrExtendArgument {
    pub fn pcr_index(&self) -> u8 {
        self.pcr_index
    }

    pub fn pcr_handle(&self) -> PcrHandle {
        self.pcr_handle
    }

    pub fn digest_values(&self) -> &DigestValues {
        &self.digest_values
    }
}

pub fn parse_pcr_extend_argument(s: &str) -> Result<PcrExtendArgument, String> {
    let (pcr_index, digests) = s
        .split_once(':')
        .ok_or_else(|| "expected format <pcr>:<alg>=<hex>".to_owned())?;
    let pcr_index = pcr_index
        .parse::<u8>()
        .map_err(|_| format!("invalid PCR index: {pcr_index}"))?;
    let pcr_handle = pcr_index_to_handle(pcr_index)?;

    let mut digest_values = DigestValues::new();
    for item in digests.split('+') {
        let (algorithm, digest) = item
            .split_once('=')
            .ok_or_else(|| format!("expected <alg>=<hex> in '{item}'"))?;
        let algorithm = parse_hashing_algorithm(algorithm)?;
        let digest_bytes = decode_hex_argument(digest, "PCR digest")?;
        let expected_size = hashing_algorithm_digest_size(algorithm)
            .ok_or_else(|| "null is not a valid PCR digest algorithm".to_owned())?;
        if digest_bytes.len() != expected_size {
            return Err(format!(
                "invalid {algorithm:?} digest size: expected {expected_size} bytes, got {}",
                digest_bytes.len()
            ));
        }
        let digest =
            Digest::try_from(digest_bytes).map_err(|e| format!("invalid PCR digest: {e}"))?;
        digest_values.set(algorithm, digest);
    }

    Ok(PcrExtendArgument {
        pcr_index,
        pcr_handle,
        digest_values,
    })
}

fn hashing_algorithm_digest_size(algorithm: HashingAlgorithm) -> Option<usize> {
    match algorithm {
        HashingAlgorithm::Sha1 => Some(20),
        HashingAlgorithm::Sha256 | HashingAlgorithm::Sm3_256 | HashingAlgorithm::Sha3_256 => {
            Some(32)
        }
        HashingAlgorithm::Sha384 | HashingAlgorithm::Sha3_384 => Some(48),
        HashingAlgorithm::Sha512 | HashingAlgorithm::Sha3_512 => Some(64),
        HashingAlgorithm::Null => None,
    }
}

fn pcr_index_to_handle(index: u8) -> Result<PcrHandle, String> {
    match index {
        0 => Ok(PcrHandle::Pcr0),
        1 => Ok(PcrHandle::Pcr1),
        2 => Ok(PcrHandle::Pcr2),
        3 => Ok(PcrHandle::Pcr3),
        4 => Ok(PcrHandle::Pcr4),
        5 => Ok(PcrHandle::Pcr5),
        6 => Ok(PcrHandle::Pcr6),
        7 => Ok(PcrHandle::Pcr7),
        8 => Ok(PcrHandle::Pcr8),
        9 => Ok(PcrHandle::Pcr9),
        10 => Ok(PcrHandle::Pcr10),
        11 => Ok(PcrHandle::Pcr11),
        12 => Ok(PcrHandle::Pcr12),
        13 => Ok(PcrHandle::Pcr13),
        14 => Ok(PcrHandle::Pcr14),
        15 => Ok(PcrHandle::Pcr15),
        16 => Ok(PcrHandle::Pcr16),
        17 => Ok(PcrHandle::Pcr17),
        18 => Ok(PcrHandle::Pcr18),
        19 => Ok(PcrHandle::Pcr19),
        20 => Ok(PcrHandle::Pcr20),
        21 => Ok(PcrHandle::Pcr21),
        22 => Ok(PcrHandle::Pcr22),
        23 => Ok(PcrHandle::Pcr23),
        24 => Ok(PcrHandle::Pcr24),
        25 => Ok(PcrHandle::Pcr25),
        26 => Ok(PcrHandle::Pcr26),
        27 => Ok(PcrHandle::Pcr27),
        28 => Ok(PcrHandle::Pcr28),
        29 => Ok(PcrHandle::Pcr29),
        30 => Ok(PcrHandle::Pcr30),
        31 => Ok(PcrHandle::Pcr31),
        _ => Err(format!("PCR index out of range: {index}")),
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

    #[test]
    fn clock_adjust_is_parsed_to_tpm_type() {
        assert_eq!(
            parse_clock_adjust("faster").unwrap(),
            ClockAdjust::CoarseFaster
        );
        assert!(parse_clock_adjust("warp").is_err());
    }

    #[test]
    fn signature_scheme_kind_is_validated_without_hash_context() {
        assert_eq!(
            parse_signature_scheme_kind("ecdsa").unwrap(),
            SignatureSchemeKind::EcDsa
        );
        assert!(parse_signature_scheme_kind("invalid").is_err());
    }

    #[test]
    fn nv_auth_entity_rejects_unknown_values() {
        assert!(matches!(
            parse_nv_auth_entity("index"),
            Ok(NvAuthEntity::NvIndex)
        ));
        assert!(parse_nv_auth_entity("typo").is_err());
    }

    #[test]
    fn command_code_list_is_parsed_atomically() {
        assert!(parse_command_code_list("unseal,0x0000015d").is_ok());
        assert!(parse_command_code_list("unseal,not-a-command").is_err());
    }

    #[test]
    fn pcr_extend_argument_rejects_invalid_input() {
        let valid = format!("7:sha256={}", "00".repeat(32));
        let parsed = parse_pcr_extend_argument(&valid).unwrap();
        assert_eq!(parsed.pcr_index(), 7);
        assert!(parse_pcr_extend_argument("32:sha256=00").is_err());
        assert!(parse_pcr_extend_argument("7:sha256=00").is_err());
        assert!(parse_pcr_extend_argument("7:sha256=not-hex").is_err());
    }

    #[test]
    fn typed_hex_structures_reject_bad_hex() {
        assert!(parse_hex_digest("00ff").is_ok());
        assert!(parse_hex_digest("xyz").is_err());
        assert!(parse_hex_name("xyz").is_err());
        assert!(parse_hex_timeout("xyz").is_err());
    }
}
