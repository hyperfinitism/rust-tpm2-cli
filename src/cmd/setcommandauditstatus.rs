// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Set or clear the audit status for a command.
///
/// Wraps TPM2_SetCommandCodeAuditStatus (raw FFI).
#[derive(Parser)]
pub struct SetCommandAuditStatusCmd {
    /// Auth hierarchy (o/owner or p/platform)
    #[arg(short = 'C', long = "hierarchy", default_value = "o")]
    pub hierarchy: String,

    /// Auth value
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Hash algorithm for the audit digest
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Command codes to set for audit (comma-separated hex)
    #[arg(long = "set-list")]
    pub set_list: Option<String>,

    /// Command codes to clear from audit (comma-separated hex)
    #[arg(long = "clear-list")]
    pub clear_list: Option<String>,
}

impl SetCommandAuditStatusCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let auth_handle = RawEsysContext::resolve_hierarchy(&self.hierarchy)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.value())?;
        }

        let audit_alg: u16 = match self.hash_algorithm.to_lowercase().as_str() {
            "sha1" => TPM2_ALG_SHA1,
            "sha256" => TPM2_ALG_SHA256,
            "sha384" => TPM2_ALG_SHA384,
            "sha512" => TPM2_ALG_SHA512,
            _ => anyhow::bail!("unknown hash algorithm: {}", self.hash_algorithm),
        };

        let set_list = parse_command_list(self.set_list.as_deref())?;
        let clear_list = parse_command_list(self.clear_list.as_deref())?;

        unsafe {
            let rc = Esys_SetCommandCodeAuditStatus(
                raw.ptr(),
                auth_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                audit_alg,
                &set_list,
                &clear_list,
            );
            if rc != 0 {
                anyhow::bail!("Esys_SetCommandCodeAuditStatus failed: 0x{rc:08x}");
            }
        }

        info!("command audit status updated");
        Ok(())
    }
}

fn parse_command_list(s: Option<&str>) -> anyhow::Result<TPML_CC> {
    let mut list = TPML_CC::default();
    if let Some(codes) = s {
        for code_str in codes.split(',') {
            let stripped = code_str
                .trim()
                .strip_prefix("0x")
                .unwrap_or(code_str.trim());
            let code: u32 = u32::from_str_radix(stripped, 16)
                .map_err(|_| anyhow::anyhow!("invalid command code: {code_str}"))?;
            list.commandCodes[list.count as usize] = code;
            list.count += 1;
        }
    }
    Ok(list)
}
