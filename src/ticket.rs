// SPDX-License-Identifier: Apache-2.0

use tss_esapi::handles::TpmHandle;
use tss_esapi::structures::{AuthTicket, CreationTicket, HashcheckTicket, Ticket, VerifiedTicket};
use tss_esapi::tss2_esys::{
    TPM2B_DIGEST, TPMT_TK_AUTH, TPMT_TK_CREATION, TPMT_TK_HASHCHECK, TPMT_TK_VERIFIED,
};

pub fn marshall_ticket(ticket: &impl Ticket) -> Vec<u8> {
    let tag = u16::from(ticket.tag());
    let hierarchy = u32::from(TpmHandle::from(ticket.hierarchy()));
    let digest = ticket.digest();

    let mut bytes = Vec::with_capacity(8 + digest.len());
    bytes.extend_from_slice(&tag.to_be_bytes());
    bytes.extend_from_slice(&hierarchy.to_be_bytes());
    bytes.extend_from_slice(&(digest.len() as u16).to_be_bytes());
    bytes.extend_from_slice(digest);
    bytes
}

pub fn parse_auth_ticket(data: &[u8]) -> anyhow::Result<AuthTicket> {
    let wire = parse_wire_ticket(data)?;
    AuthTicket::try_from(TPMT_TK_AUTH {
        tag: wire.tag,
        hierarchy: wire.hierarchy,
        digest: wire.digest,
    })
    .map_err(|e| anyhow::anyhow!("invalid authorization ticket: {e}"))
}

pub fn parse_creation_ticket(data: &[u8]) -> anyhow::Result<CreationTicket> {
    let wire = parse_wire_ticket(data)?;
    CreationTicket::try_from(TPMT_TK_CREATION {
        tag: wire.tag,
        hierarchy: wire.hierarchy,
        digest: wire.digest,
    })
    .map_err(|e| anyhow::anyhow!("invalid creation ticket: {e}"))
}

pub fn parse_hashcheck_ticket(data: &[u8]) -> anyhow::Result<HashcheckTicket> {
    let wire = parse_wire_ticket(data)?;
    HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: wire.tag,
        hierarchy: wire.hierarchy,
        digest: wire.digest,
    })
    .map_err(|e| anyhow::anyhow!("invalid hashcheck ticket: {e}"))
}

pub fn parse_verified_ticket(data: &[u8]) -> anyhow::Result<VerifiedTicket> {
    let wire = parse_wire_ticket(data)?;
    VerifiedTicket::try_from(TPMT_TK_VERIFIED {
        tag: wire.tag,
        hierarchy: wire.hierarchy,
        digest: wire.digest,
    })
    .map_err(|e| anyhow::anyhow!("invalid verification ticket: {e}"))
}

struct WireTicket {
    tag: u16,
    hierarchy: u32,
    digest: TPM2B_DIGEST,
}

fn parse_wire_ticket(data: &[u8]) -> anyhow::Result<WireTicket> {
    if data.len() < 8 {
        anyhow::bail!("ticket is shorter than the 8-byte header");
    }

    let digest_size = usize::from(u16::from_be_bytes([data[6], data[7]]));
    let mut digest = TPM2B_DIGEST::default();
    if digest_size > digest.buffer.len() {
        anyhow::bail!("ticket digest is too large: {digest_size} bytes");
    }
    if data.len() != 8 + digest_size {
        anyhow::bail!(
            "ticket length mismatch: expected {}, got {}",
            8 + digest_size,
            data.len()
        );
    }

    digest.size = digest_size as u16;
    digest.buffer[..digest_size].copy_from_slice(&data[8..]);
    Ok(WireTicket {
        tag: u16::from_be_bytes([data[0], data[1]]),
        hierarchy: u32::from_be_bytes([data[2], data[3], data[4], data[5]]),
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashcheck_ticket_round_trips_wire_format() {
        let ticket = HashcheckTicket::default();
        let bytes = marshall_ticket(&ticket);
        let parsed = parse_hashcheck_ticket(&bytes).unwrap();
        assert_eq!(parsed.tag(), ticket.tag());
        assert_eq!(parsed.hierarchy(), ticket.hierarchy());
        assert_eq!(parsed.digest(), ticket.digest());
    }

    #[test]
    fn ticket_parser_rejects_trailing_bytes() {
        let mut bytes = marshall_ticket(&HashcheckTicket::default());
        bytes.push(0);
        assert!(parse_hashcheck_ticket(&bytes).is_err());
    }
}
