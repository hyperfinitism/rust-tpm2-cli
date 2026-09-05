// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use serde_json::json;

use crate::cli::GlobalOpts;
use crate::context::create_context;
#[derive(Parser)]
pub struct ReadClockCmd {}

impl ReadClockCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let current_time = ctx.read_clock().context("TPM2_ReadClock failed")?;
        let clock_info = current_time.clock_info();
        let output = json!({
            "time": current_time.time(),
            "clock_info": {
                "clock": clock_info.clock(),
                "reset_count": clock_info.reset_count(),
                "restart_count": clock_info.restart_count(),
                "safe": clock_info.safe(),
            }
        });

        println!("{}", serde_json::to_string_pretty(&output)?);

        Ok(())
    }
}
