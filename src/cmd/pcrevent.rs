// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Extend a PCR with event data (TPM hashes the data).
///
/// Wraps TPM2_PCR_Event (raw FFI). Unlike pcrextend, the TPM hashes
/// the data rather than the caller.
#[derive(Parser)]
pub struct PcrEventCmd {
    /// PCR index to extend
    #[arg()]
    pub pcr_index: u8,

    /// Auth value for the PCR (if needed)
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Input data file to hash and extend
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,
}

impl PcrEventCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        let pcr_tpm_handle: u32 = self.pcr_index as u32;
        let pcr_handle: ESYS_TR = if pcr_tpm_handle < TPM2_MAX_PCRS {
            pcr_tpm_handle
        } else {
            raw.tr_from_tpm_public(pcr_tpm_handle)?
        };

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(pcr_handle, auth.as_bytes())?;
        }

        let data = std::fs::read(&self.input)
            .with_context(|| format!("reading input from {}", self.input.display()))?;

        let mut event_data = TPM2B_EVENT::default();
        let len = data.len().min(event_data.buffer.len());
        event_data.size = len as u16;
        event_data.buffer[..len].copy_from_slice(&data[..len]);

        unsafe {
            let mut digests: *mut TPML_DIGEST_VALUES = std::ptr::null_mut();
            let rc = Esys_PCR_Event(
                raw.ptr(),
                pcr_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &event_data,
                &mut digests,
            );
            if rc != 0 {
                anyhow::bail!("Esys_PCR_Event failed: 0x{rc:08x}");
            }

            if !digests.is_null() {
                let d = &*digests;
                info!("PCR {} extended with {} digest(s)", self.pcr_index, d.count);
                Esys_Free(digests as *mut _);
            }
        }

        Ok(())
    }
}
