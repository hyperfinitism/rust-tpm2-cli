// SPDX-License-Identifier: Apache-2.0

use anyhow::bail;
use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Allocate PCR banks with the specified hash algorithms.
///
/// Wraps TPM2_PCR_Allocate (raw FFI). Changes take effect after TPM reset.
#[derive(Parser)]
pub struct PcrAllocateCmd {
    /// Auth hierarchy (p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "p", value_parser = parse::parse_esys_hierarchy)]
    pub hierarchy: u32,

    /// Auth value
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// PCR allocation (e.g. sha256:0,1,2+sha1:all)
    #[arg()]
    pub allocation: String,
}

impl PcrAllocateCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let auth_handle = self.hierarchy;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.value())?;
        }

        let pcr_allocation = build_pcr_allocation(&self.allocation)?;

        unsafe {
            let mut allocation_success: TPMI_YES_NO = 0;
            let mut max_pcr: u32 = 0;
            let mut size_needed: u32 = 0;
            let mut size_available: u32 = 0;

            let rc = Esys_PCR_Allocate(
                raw.ptr(),
                auth_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &pcr_allocation,
                &mut allocation_success,
                &mut max_pcr,
                &mut size_needed,
                &mut size_available,
            );
            if rc != 0 {
                bail!("Esys_PCR_Allocate failed: 0x{rc:08x}");
            }

            if allocation_success != 0 {
                info!(
                    "PCR allocation succeeded (max_pcr={max_pcr}, needed={size_needed}, available={size_available})"
                );
            } else {
                info!(
                    "PCR allocation will take effect after TPM reset (needed={size_needed}, available={size_available})"
                );
            }
        }

        Ok(())
    }
}

fn build_pcr_allocation(spec: &str) -> anyhow::Result<TPML_PCR_SELECTION> {
    let mut selection = TPML_PCR_SELECTION::default();
    let mut count = 0u32;

    for bank_spec in spec.split('+') {
        let (alg_str, indices_str) = bank_spec
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid PCR spec: missing ':' in '{bank_spec}'"))?;

        let alg_id: u16 = match alg_str.to_lowercase().as_str() {
            "sha1" | "sha" => TPM2_ALG_SHA1,
            "sha256" => TPM2_ALG_SHA256,
            "sha384" => TPM2_ALG_SHA384,
            "sha512" => TPM2_ALG_SHA512,
            _ => anyhow::bail!("unknown hash algorithm: {alg_str}"),
        };

        let mut pcr_select = [0u8; 4]; // 32 PCRs max, pcrSelect is [u8; 4]
        if indices_str.eq_ignore_ascii_case("all") {
            pcr_select = [0xFF, 0xFF, 0xFF, 0x00];
        } else {
            for idx_str in indices_str.split(',') {
                let idx: u8 = idx_str
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid PCR index: {idx_str}"))?;
                if idx >= 24 {
                    bail!("PCR index out of range: {idx}");
                }
                pcr_select[(idx / 8) as usize] |= 1 << (idx % 8);
            }
        }

        selection.pcrSelections[count as usize] = TPMS_PCR_SELECTION {
            hash: alg_id,
            sizeofSelect: 3,
            pcrSelect: pcr_select,
        };
        count += 1;
    }

    selection.count = count;
    Ok(selection)
}
