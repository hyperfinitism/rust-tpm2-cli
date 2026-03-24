// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Get the results of a TPM self test.
///
/// Wraps TPM2_GetTestResult: returns the test result data and the
/// overall pass/fail status.
#[derive(Parser)]
pub struct GetTestResultCmd {}

impl GetTestResultCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let (data, result) = ctx
            .execute_without_session(|ctx| ctx.get_test_result())
            .context("TPM2_GetTestResult failed")?;

        let status = match result {
            Ok(()) => "success",
            Err(_) => "failure",
        };

        println!("status: {status}");
        if !data.as_bytes().is_empty() {
            println!("data: {}", hex::encode(data.as_bytes()));
        }

        Ok(())
    }
}
