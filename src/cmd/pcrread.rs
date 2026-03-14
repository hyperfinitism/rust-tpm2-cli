// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use log::info;
use tss_esapi::structures::PcrSlot;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;
use crate::parse;
use crate::pcr;

/// Read PCR values.
///
/// Specify PCR banks + indices like `sha256:0,1,2+sha1:0,1`.
/// Use `all` for all indices in a bank: `sha256:all`.
/// Without arguments reads all PCR banks.
#[derive(Parser)]
pub struct PcrReadCmd {
    /// PCR selection list (e.g. sha256:0,1,2+sha1:all)
    pub pcr_list: Option<String>,

    /// Output binary PCR values to a file
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

impl PcrReadCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let selection = match &self.pcr_list {
            Some(spec) => parse::parse_pcr_selection(spec)?,
            None => parse::default_pcr_selection()?,
        };

        // TPM2_PCR_Read returns at most 8 digests per call; loop until all
        // requested PCRs have been read.
        let chunks = pcr::pcr_read_all(&mut ctx, selection)?;

        // Print results and optionally accumulate raw bytes for file output.
        let mut raw: Vec<u8> = Vec::new();
        for (read_sel, digests) in &chunks {
            let mut idx = 0;
            for sel in read_sel.get_selections() {
                let alg = sel.hashing_algorithm();
                let selected: Vec<PcrSlot> = sel.selected().into_iter().collect();
                for slot in &selected {
                    if idx < digests.value().len() {
                        let digest = digests.value()[idx].value();
                        let pcr_num = parse::pcr_slot_to_index(*slot);
                        println!("  {alg:?}:");
                        println!("    {pcr_num} : 0x{}", hex::encode(digest));
                        if self.output.is_some() {
                            raw.extend_from_slice(digest);
                        }
                        idx += 1;
                    }
                }
            }
        }

        // Optionally write raw binary of all digests to file
        if let Some(ref path) = self.output {
            output::write_to_file(path, &raw)?;
            info!("wrote PCR binary data to {}", path.display());
        }

        Ok(())
    }
}
