// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;

/// Start a hash sequence on the TPM.
///
/// Wraps TPM2_HashSequenceStart: begins an incremental hash computation.
/// The returned sequence handle is saved to a context file for use with
/// `sequenceupdate` and `sequencecomplete`.
#[derive(Parser)]
pub struct HashSequenceStartCmd {
    /// Hash algorithm (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Output file for the sequence context
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl HashSequenceStartCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let hash_alg = self.hash_algorithm;

        let seq_handle = ctx
            .hash_sequence_start(hash_alg, None)
            .context("TPM2_HashSequenceStart failed")?;

        // Save the sequence handle context.
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
