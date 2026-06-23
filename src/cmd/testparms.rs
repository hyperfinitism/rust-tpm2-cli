// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::structures::PublicParameters;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
#[derive(Parser)]
pub struct TestParmsCmd {
    /// Algorithm parameters to test. Format: <type>
    /// Supported: rsa, rsa2048, rsa3072, rsa4096,
    ///            aes, aes128, aes192, aes256,
    ///            keyedhash, hmac, xor
    #[arg(value_parser = parse::parse_public_parameters)]
    pub parameters: PublicParameters,
}

impl TestParmsCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        match ctx.execute_without_session(|ctx| ctx.test_parms(self.parameters)) {
            Ok(()) => {
                info!("parameters are supported");
                println!("supported");
            }
            Err(e) => {
                println!("not supported: {e}");
            }
        }

        Ok(())
    }
}
