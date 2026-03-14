// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Run the TPM self test.
///
/// Wraps TPM2_SelfTest.
#[derive(Parser)]
pub struct SelfTestCmd {
    /// Run full self test (default: true)
    #[arg(long = "full-test", default_value = "true")]
    pub full_test: bool,
}

impl SelfTestCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        ctx.execute_without_session(|ctx| ctx.self_test(self.full_test))
            .context("TPM2_SelfTest failed")?;

        info!("self test completed (full={})", self.full_test);
        Ok(())
    }
}
