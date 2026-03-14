// SPDX-License-Identifier: Apache-2.0

use anyhow::bail;
use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::raw_esys::RawEsysContext;

/// Run incremental self test on specified algorithms.
///
/// Wraps TPM2_IncrementalSelfTest (raw FFI).
#[derive(Parser)]
pub struct IncrementalSelfTestCmd {
    /// Algorithms to test (comma-separated: sha1,sha256,rsa,ecc,aes)
    #[arg(default_value = "sha256")]
    pub algorithms: String,
}

impl IncrementalSelfTestCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        let alg_ids = parse_algorithm_list(&self.algorithms)?;

        let mut alg_list = TPML_ALG {
            count: alg_ids.len() as u32,
            ..Default::default()
        };
        for (i, &alg) in alg_ids.iter().enumerate() {
            alg_list.algorithms[i] = alg;
        }

        unsafe {
            let mut to_do_list: *mut TPML_ALG = std::ptr::null_mut();
            let rc = Esys_IncrementalSelfTest(
                raw.ptr(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &alg_list,
                &mut to_do_list,
            );
            if rc != 0 {
                bail!("Esys_IncrementalSelfTest failed: 0x{rc:08x}");
            }

            if !to_do_list.is_null() {
                let todo = &*to_do_list;
                if todo.count > 0 {
                    info!("{} algorithms still need testing", todo.count);
                } else {
                    info!("all requested algorithms tested");
                }
                Esys_Free(to_do_list as *mut _);
            }
        }

        Ok(())
    }
}

fn parse_algorithm_list(s: &str) -> anyhow::Result<Vec<u16>> {
    s.split(',')
        .map(|alg| match alg.trim().to_lowercase().as_str() {
            "sha1" | "sha" => Ok(TPM2_ALG_SHA1),
            "sha256" => Ok(TPM2_ALG_SHA256),
            "sha384" => Ok(TPM2_ALG_SHA384),
            "sha512" => Ok(TPM2_ALG_SHA512),
            "rsa" => Ok(TPM2_ALG_RSA),
            "ecc" => Ok(TPM2_ALG_ECC),
            "aes" => Ok(TPM2_ALG_AES),
            "hmac" => Ok(TPM2_ALG_HMAC),
            _ => bail!("unknown algorithm: {alg}"),
        })
        .collect()
}
