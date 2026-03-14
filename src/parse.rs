// SPDX-License-Identifier: Apache-2.0

//! Pure CLI argument parsers.
//!
//! Every function in this module converts a CLI string into a typed value
//! without touching a TPM context.  Functions that need a [`tss_esapi::Context`]
//! live in [`crate::handle`] or [`crate::session`].

use anyhow::{Context, bail};
use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::handles::AuthHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SymmetricMode};
use tss_esapi::interface_types::resource_handles::{Hierarchy, HierarchyAuth, Provision};
use tss_esapi::structures::{
    Auth, HashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, SignatureScheme,
};

use crate::error::Tpm2Error;

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
// Hashing algorithm
// ---------------------------------------------------------------------------

/// Parse a hashing algorithm name.
pub fn parse_hashing_algorithm(s: &str) -> anyhow::Result<HashingAlgorithm> {
    match s.to_lowercase().as_str() {
        "sha1" | "sha" => Ok(HashingAlgorithm::Sha1),
        "sha256" => Ok(HashingAlgorithm::Sha256),
        "sha384" => Ok(HashingAlgorithm::Sha384),
        "sha512" => Ok(HashingAlgorithm::Sha512),
        "sm3_256" | "sm3" => Ok(HashingAlgorithm::Sm3_256),
        "sha3_256" => Ok(HashingAlgorithm::Sha3_256),
        "sha3_384" => Ok(HashingAlgorithm::Sha3_384),
        "sha3_512" => Ok(HashingAlgorithm::Sha3_512),
        _ => bail!("unknown hashing algorithm: {s}"),
    }
}

// ---------------------------------------------------------------------------
// Signature scheme
// ---------------------------------------------------------------------------

/// Parse a signature scheme name together with the hashing algorithm it uses.
pub fn parse_signature_scheme(
    s: &str,
    hash_alg: HashingAlgorithm,
) -> anyhow::Result<SignatureScheme> {
    let hs = HashScheme::new(hash_alg);
    match s.to_lowercase().as_str() {
        "rsassa" => Ok(SignatureScheme::RsaSsa { hash_scheme: hs }),
        "rsapss" => Ok(SignatureScheme::RsaPss { hash_scheme: hs }),
        "ecdsa" => Ok(SignatureScheme::EcDsa { hash_scheme: hs }),
        "null" => Ok(SignatureScheme::Null),
        _ => bail!("unsupported signature scheme: {s}"),
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
// Authorization value
// ---------------------------------------------------------------------------

/// Parse an authorization value from a CLI string.
///
/// Supported formats:
/// - `hex:<hex_bytes>` — hex-encoded byte string
/// - `file:<path>`     — read raw bytes from file
/// - `<string>`        — plain UTF-8 password (fallback)
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
pub fn parse_nv_attributes(s: &str) -> anyhow::Result<tss_esapi::attributes::NvIndexAttributes> {
    let mut builder = NvIndexAttributesBuilder::new();

    for attr in s.split('|') {
        builder = match attr.trim().to_lowercase().as_str() {
            "ownerwrite" => builder.with_owner_write(true),
            "ownerread" => builder.with_owner_read(true),
            "authwrite" => builder.with_auth_write(true),
            "authread" => builder.with_auth_read(true),
            "policywrite" => builder.with_policy_write(true),
            "policyread" => builder.with_policy_read(true),
            "ppwrite" => builder.with_pp_write(true),
            "ppread" => builder.with_pp_read(true),
            "writedefine" => builder.with_write_define(true),
            "written" => builder.with_written(true),
            "writeall" => builder.with_write_all(true),
            "read_stclear" => builder.with_read_stclear(true),
            "write_stclear" => builder.with_write_stclear(true),
            "platformcreate" => builder.with_platform_create(true),
            _ => anyhow::bail!("unknown NV attribute: {attr}"),
        };
    }

    builder.build().context("failed to build NV attributes")
}

// ---------------------------------------------------------------------------
// PCR selection
// ---------------------------------------------------------------------------

/// Parse a PCR selection string like `sha256:0,1,2+sha1:all`.
pub fn parse_pcr_selection(spec: &str) -> anyhow::Result<PcrSelectionList> {
    let mut builder = PcrSelectionListBuilder::new();

    for bank_spec in spec.split('+') {
        let (alg_str, indices_str) = bank_spec
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid PCR spec: missing ':' in '{bank_spec}'"))?;

        let alg = parse_hashing_algorithm(alg_str)?;
        let slots = parse_pcr_indices(indices_str)?;
        builder = builder.with_selection(alg, &slots);
    }

    builder
        .build()
        .context("failed to build PCR selection list")
}

/// Build a default selection covering sha256 and sha1, all 24 PCRs.
pub fn default_pcr_selection() -> anyhow::Result<PcrSelectionList> {
    let all_slots = all_pcr_slots();
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &all_slots)
        .with_selection(HashingAlgorithm::Sha1, &all_slots)
        .build()
        .context("failed to build default PCR selection list")
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

// ---------------------------------------------------------------------------
// Symmetric mode
// ---------------------------------------------------------------------------

/// Parse a symmetric cipher mode name.
pub fn parse_symmetric_mode(s: &str) -> anyhow::Result<SymmetricMode> {
    match s.to_lowercase().as_str() {
        "cfb" => Ok(SymmetricMode::Cfb),
        "cbc" => Ok(SymmetricMode::Cbc),
        "ecb" => Ok(SymmetricMode::Ecb),
        "ofb" => Ok(SymmetricMode::Ofb),
        "ctr" => Ok(SymmetricMode::Ctr),
        "null" => Ok(SymmetricMode::Null),
        _ => bail!("unsupported symmetric mode: {s}"),
    }
}

// ---------------------------------------------------------------------------
// Qualification data
// ---------------------------------------------------------------------------

/// Parse qualification data from an explicit hex string.
pub fn parse_qualification_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).map_err(|e| anyhow::anyhow!("invalid hex qualification data '{s}': {e}"))
}

/// Read qualification data from a file path.
pub fn parse_qualification_file(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading qualification file: {}", path.display()))
}

// ---------------------------------------------------------------------------
// TPM2 comparison operation
// ---------------------------------------------------------------------------

/// Parse a TPM2_EO_* comparison operation name to its `u16` constant.
pub fn parse_tpm2_operation(s: &str) -> anyhow::Result<u16> {
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
        _ => bail!("unknown operation: {s}; expected eq/neq/sgt/ugt/slt/ult/sge/uge/sle/ule/bs/bc"),
    }
}

fn parse_pcr_indices(s: &str) -> anyhow::Result<Vec<PcrSlot>> {
    if s.eq_ignore_ascii_case("all") {
        return Ok(all_pcr_slots());
    }

    s.split(',')
        .map(|tok| {
            let idx: u8 = tok
                .trim()
                .parse()
                .with_context(|| format!("invalid PCR index: {tok}"))?;
            index_to_pcr_slot(idx).ok_or_else(|| anyhow::anyhow!("PCR index out of range: {idx}"))
        })
        .collect()
}

fn all_pcr_slots() -> Vec<PcrSlot> {
    (0u8..24).filter_map(index_to_pcr_slot).collect()
}
