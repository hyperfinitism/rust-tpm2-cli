// SPDX-License-Identifier: Apache-2.0

//! PCR-specific TPM operations.
//!
//! Pure PCR argument parsers (selection strings, slot conversion, etc.) have
//! moved to [`crate::parse`].  This module keeps only operations that require
//! a live [`tss_esapi::Context`].

use anyhow::Context;
use tss_esapi::structures::{DigestList, PcrSelectionList};

/// Read all PCRs in `selection`, issuing multiple `TPM2_PCR_Read` calls as
/// needed because the TPM returns at most 8 digests per call.
///
/// Returns a vec of `(pcrSelectionOut, digests)` pairs — one per TPM call —
/// preserving the ordering needed to correlate each digest with its slot.
pub fn pcr_read_all(
    ctx: &mut tss_esapi::Context,
    selection: PcrSelectionList,
) -> anyhow::Result<Vec<(PcrSelectionList, DigestList)>> {
    let mut remaining = selection;
    let mut chunks = Vec::new();

    loop {
        if remaining.is_empty() {
            break;
        }

        let (_, read_sel, digests) = ctx
            .execute_without_session(|ctx| ctx.pcr_read(remaining.clone()))
            .context("TPM2_PCR_Read failed")?;

        if read_sel.is_empty() {
            break;
        }

        remaining
            .subtract(&read_sel)
            .context("failed to subtract returned PCR selection")?;

        chunks.push((read_sel, digests));
    }

    Ok(chunks)
}
