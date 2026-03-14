use std::io::{Cursor, Read as IoRead};
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use serde_json::{Value, json};

use crate::cli::GlobalOpts;

/// Parse and display a binary TPM2 event log.
///
/// Reads a TCG PC Client Platform Firmware Profile event log
/// (binary_bios_measurements) and prints the entries as JSON.
/// Default path: /sys/kernel/security/tpm0/binary_bios_measurements
#[derive(Parser)]
pub struct EventLogCmd {
    /// Path to the binary event log file
    #[arg(default_value = "/sys/kernel/security/tpm0/binary_bios_measurements")]
    pub file: PathBuf,
}

impl EventLogCmd {
    pub fn execute(&self, _global: &GlobalOpts) -> anyhow::Result<()> {
        let data = std::fs::read(&self.file)
            .with_context(|| format!("reading event log: {}", self.file.display()))?;

        let events = parse_event_log(&data)?;
        println!("{}", serde_json::to_string_pretty(&events)?);
        Ok(())
    }
}

// -----------------------------------------------------------------------
// Event type names
// -----------------------------------------------------------------------

fn event_type_name(ty: u32) -> &'static str {
    match ty {
        0x00000000 => "EV_PREBOOT_CERT",
        0x00000001 => "EV_POST_CODE",
        0x00000002 => "EV_UNUSED",
        0x00000003 => "EV_NO_ACTION",
        0x00000004 => "EV_SEPARATOR",
        0x00000005 => "EV_ACTION",
        0x00000006 => "EV_EVENT_TAG",
        0x00000007 => "EV_S_CRTM_CONTENTS",
        0x00000008 => "EV_S_CRTM_VERSION",
        0x00000009 => "EV_CPU_MICROCODE",
        0x0000000A => "EV_PLATFORM_CONFIG_FLAGS",
        0x0000000B => "EV_TABLE_OF_DEVICES",
        0x0000000C => "EV_COMPACT_HASH",
        0x0000000D => "EV_IPL",
        0x0000000E => "EV_IPL_PARTITION_DATA",
        0x0000000F => "EV_NONHOST_CODE",
        0x00000010 => "EV_NONHOST_CONFIG",
        0x00000011 => "EV_NONHOST_INFO",
        0x00000012 => "EV_OMIT_BOOT_DEVICE_EVENTS",
        0x80000001 => "EV_EFI_VARIABLE_DRIVER_CONFIG",
        0x80000002 => "EV_EFI_VARIABLE_BOOT",
        0x80000003 => "EV_EFI_BOOT_SERVICES_APPLICATION",
        0x80000004 => "EV_EFI_BOOT_SERVICES_DRIVER",
        0x80000005 => "EV_EFI_RUNTIME_SERVICES_DRIVER",
        0x80000006 => "EV_EFI_GPT_EVENT",
        0x80000007 => "EV_EFI_ACTION",
        0x80000008 => "EV_EFI_PLATFORM_FIRMWARE_BLOB",
        0x80000009 => "EV_EFI_HANDOFF_TABLES",
        0x8000000A => "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        0x8000000B => "EV_EFI_HANDOFF_TABLES2",
        0x8000000C => "EV_EFI_VARIABLE_BOOT2",
        0x80000010 => "EV_EFI_HCRTM_EVENT",
        0x800000E0 => "EV_EFI_VARIABLE_AUTHORITY",
        0x800000E1 => "EV_EFI_SPDM_FIRMWARE_BLOB",
        0x800000E2 => "EV_EFI_SPDM_FIRMWARE_CONFIG",
        _ => "UNKNOWN",
    }
}

fn hash_alg_name(alg: u16) -> &'static str {
    match alg {
        0x0004 => "sha1",
        0x000B => "sha256",
        0x000C => "sha384",
        0x000D => "sha512",
        0x0012 => "sm3_256",
        0x0027 => "sha3_256",
        0x0028 => "sha3_384",
        0x0029 => "sha3_512",
        _ => "unknown",
    }
}

fn hash_alg_digest_size(alg: u16) -> Option<usize> {
    match alg {
        0x0004 => Some(20), // SHA-1
        0x000B => Some(32), // SHA-256
        0x000C => Some(48), // SHA-384
        0x000D => Some(64), // SHA-512
        0x0012 => Some(32), // SM3-256
        0x0027 => Some(32), // SHA3-256
        0x0028 => Some(48), // SHA3-384
        0x0029 => Some(64), // SHA3-512
        _ => None,
    }
}

// -----------------------------------------------------------------------
// Binary reader helpers
// -----------------------------------------------------------------------

fn read_u16(cur: &mut Cursor<&[u8]>) -> anyhow::Result<u16> {
    let mut buf = [0u8; 2];
    cur.read_exact(&mut buf)
        .context("unexpected end of event log")?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(cur: &mut Cursor<&[u8]>) -> anyhow::Result<u32> {
    let mut buf = [0u8; 4];
    cur.read_exact(&mut buf)
        .context("unexpected end of event log")?;
    Ok(u32::from_le_bytes(buf))
}

fn read_bytes(cur: &mut Cursor<&[u8]>, n: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    cur.read_exact(&mut buf)
        .context("unexpected end of event log")?;
    Ok(buf)
}

// -----------------------------------------------------------------------
// Spec ID event parsing (determines crypto-agile vs legacy format)
// -----------------------------------------------------------------------

struct DigestSpec {
    alg_id: u16,
    digest_size: u16,
}

/// Parse the TCG_EfiSpecIDEvent to determine digest algorithms in use.
fn parse_spec_id_event(event_data: &[u8]) -> anyhow::Result<Vec<DigestSpec>> {
    let mut cur = Cursor::new(event_data);

    // Signature: 16 bytes "Spec ID Event03\0"
    let sig = read_bytes(&mut cur, 16)?;
    let sig_str = String::from_utf8_lossy(&sig);
    if !sig_str.starts_with("Spec ID Event") {
        bail!("not a TCG Spec ID Event: {sig_str:?}");
    }

    // platformClass (u32), specVersionMinor (u8), specVersionMajor (u8),
    // specErrata (u8), uintnSize (u8)
    let _platform_class = read_u32(&mut cur)?;
    let mut ver = [0u8; 4];
    cur.read_exact(&mut ver)?;

    let num_algorithms = read_u32(&mut cur)?;
    let mut specs = Vec::new();
    for _ in 0..num_algorithms {
        let alg_id = read_u16(&mut cur)?;
        let digest_size = read_u16(&mut cur)?;
        specs.push(DigestSpec {
            alg_id,
            digest_size,
        });
    }

    Ok(specs)
}

// -----------------------------------------------------------------------
// Event log parser
// -----------------------------------------------------------------------

fn parse_event_log(data: &[u8]) -> anyhow::Result<Value> {
    if data.len() < 32 {
        bail!("event log too short ({} bytes)", data.len());
    }

    let mut cur = Cursor::new(data);
    let mut events = Vec::new();

    // First event is always legacy format (TCG_PCClientPCREvent).
    let first = parse_legacy_event(&mut cur)?;
    let digest_specs = parse_spec_id_event_from_entry(&first)?;
    events.push(first);

    // Remaining events use the crypto-agile format if we got specs.
    if digest_specs.is_empty() {
        // Legacy mode: all events are SHA-1 only.
        while cur.position() < data.len() as u64 {
            match parse_legacy_event(&mut cur) {
                Ok(ev) => events.push(ev),
                Err(_) => break,
            }
        }
    } else {
        while cur.position() < data.len() as u64 {
            match parse_crypto_agile_event(&mut cur, &digest_specs) {
                Ok(ev) => events.push(ev),
                Err(_) => break,
            }
        }
    }

    Ok(Value::Array(events))
}

fn parse_spec_id_event_from_entry(event: &Value) -> anyhow::Result<Vec<DigestSpec>> {
    let event_type = event.get("EventType").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    if event_type != 0x03 {
        // Not EV_NO_ACTION — return empty (legacy mode).
        return Ok(Vec::new());
    }

    let event_data_hex = event
        .get("EventData")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Ok(event_data) = hex::decode(event_data_hex)
        && let Ok(specs) = parse_spec_id_event(&event_data)
    {
        return Ok(specs);
    }

    Ok(Vec::new())
}

/// Parse a legacy TCG_PCClientPCREvent (SHA-1 only, first event).
fn parse_legacy_event(cur: &mut Cursor<&[u8]>) -> anyhow::Result<Value> {
    let pcr_index = read_u32(cur)?;
    let event_type = read_u32(cur)?;
    let sha1_digest = read_bytes(cur, 20)?;
    let event_size = read_u32(cur)? as usize;
    let event_data = read_bytes(cur, event_size)?;

    Ok(json!({
        "PCRIndex": pcr_index,
        "EventType": event_type,
        "EventTypeName": event_type_name(event_type),
        "Digests": {
            "sha1": hex::encode(&sha1_digest),
        },
        "EventSize": event_size,
        "EventData": hex::encode(&event_data),
    }))
}

/// Parse a TCG_PCR_EVENT2 (crypto-agile format).
fn parse_crypto_agile_event(
    cur: &mut Cursor<&[u8]>,
    specs: &[DigestSpec],
) -> anyhow::Result<Value> {
    let pcr_index = read_u32(cur)?;
    let event_type = read_u32(cur)?;
    let digest_count = read_u32(cur)?;

    let mut digests = serde_json::Map::new();
    for _ in 0..digest_count {
        let alg_id = read_u16(cur)?;
        // Find digest size from spec or fall back to known sizes.
        let size = specs
            .iter()
            .find(|s| s.alg_id == alg_id)
            .map(|s| s.digest_size as usize)
            .or_else(|| hash_alg_digest_size(alg_id))
            .ok_or_else(|| anyhow::anyhow!("unknown digest algorithm 0x{alg_id:04x}"))?;
        let digest = read_bytes(cur, size)?;
        digests.insert(
            hash_alg_name(alg_id).to_string(),
            Value::String(hex::encode(&digest)),
        );
    }

    let event_size = read_u32(cur)? as usize;
    let event_data = read_bytes(cur, event_size)?;

    Ok(json!({
        "PCRIndex": pcr_index,
        "EventType": event_type,
        "EventTypeName": event_type_name(event_type),
        "Digests": Value::Object(digests),
        "EventSize": event_size,
        "EventData": hex::encode(&event_data),
    }))
}
