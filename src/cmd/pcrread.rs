// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use log::info;
use tss_esapi::structures::PcrSlot;

use tss_esapi::structures::PcrSelectionList;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;
use crate::parse;
use crate::pcr;
#[derive(Parser)]
pub struct PcrReadCmd {
    /// PCR selection list (e.g. sha256:0,1,2+sha1:all)
    #[arg(default_value = "sha256:all+sha1:all", value_parser = parse::parse_pcr_selection)]
    pub pcr_list: PcrSelectionList,

    /// Output binary PCR values to a file
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
}

impl PcrReadCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let selection = self.pcr_list.clone();
        let chunks = pcr::pcr_read_all(&mut ctx, selection)?;
        let mut raw: Vec<u8> = Vec::new();
        for (read_sel, digests) in &chunks {
            let mut idx = 0;
            for sel in read_sel.get_selections() {
                let alg = sel.hashing_algorithm();
                let selected: Vec<PcrSlot> = sel.selected().into_iter().collect();
                for slot in &selected {
                    if idx < digests.value().len() {
                        let digest = digests.value()[idx].as_bytes();
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
        if let Some(ref path) = self.output {
            output::write_to_file(path, &raw)?;
            info!("wrote PCR binary data to {}", path.display());
        }

        Ok(())
    }
}
