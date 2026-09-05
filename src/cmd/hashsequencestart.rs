// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
#[derive(Parser)]
pub struct HashSequenceStartCmd {
    /// Hash algorithm
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Authorization value for the new sequence
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Output file for the sequence context
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl HashSequenceStartCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let hash_alg = self.hash_algorithm;

        let seq_handle = ctx
            .hash_sequence_start(hash_alg, self.auth.clone())
            .context("TPM2_HashSequenceStart failed")?;
        let saved = ctx
            .context_save(seq_handle)
            .context("context_save failed")?;
        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.output, json)?;

        info!(
            "hash sequence started, context saved to {}",
            self.output.display()
        );
        Ok(())
    }
}
