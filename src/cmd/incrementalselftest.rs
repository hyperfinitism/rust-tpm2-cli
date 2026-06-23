// SPDX-License-Identifier: Apache-2.0

use anyhow::bail;
use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse::{self, AlgorithmIdentifierList};
use crate::raw_esys::RawEsysContext;
#[derive(Parser)]
pub struct IncrementalSelfTestCmd {
    /// Algorithms to test (comma-separated: sha1,sha256,rsa,ecc,aes)
    #[arg(default_value = "sha256", value_parser = parse::parse_algorithm_identifier_list)]
    pub algorithms: AlgorithmIdentifierList,
}

impl IncrementalSelfTestCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_ref())?;

        let mut alg_list = TPML_ALG {
            count: self.algorithms.as_slice().len() as u32,
            ..Default::default()
        };
        for (i, &alg) in self.algorithms.as_slice().iter().enumerate() {
            alg_list.algorithms[i] = alg;
        }

        // Raw ESYS fallback: rust-tss-esapi does not expose TPM2_IncrementalSelfTest.
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
