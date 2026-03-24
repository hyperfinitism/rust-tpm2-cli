// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::MaxBuffer;
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;

use tss_esapi::interface_types::reserved_handles::Hierarchy;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;
use crate::parse;

/// Compute a hash using the TPM.
///
/// Reads data from stdin or a file and produces a hash digest.
#[derive(Parser)]
pub struct HashCmd {
    /// Hash algorithm (sha1, sha256, sha384, sha512)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub algorithm: String,

    /// Hierarchy for the ticket (owner, endorsement, platform, null)
    #[arg(short = 'C', long = "hierarchy", default_value = "owner", value_parser = parse::parse_hierarchy)]
    pub hierarchy: Hierarchy,

    /// Input file (default: stdin)
    pub input_file: Option<PathBuf>,

    /// Output hash as hex string
    #[arg(long)]
    pub hex: bool,

    /// Output file for the hash digest
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Output file for the ticket
    #[arg(short = 't', long = "ticket")]
    pub ticket: Option<PathBuf>,
}

impl HashCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let alg = parse::parse_hashing_algorithm(&self.algorithm)?;

        let data = read_input(&self.input_file)?;
        let buffer =
            MaxBuffer::try_from(data).map_err(|e| anyhow::anyhow!("input too large: {e}"))?;

        let (digest, ticket) = ctx
            .execute_without_session(|ctx| ctx.hash(buffer.clone(), alg, self.hierarchy))
            .context("TPM2_Hash failed")?;

        let bytes = digest.as_bytes();

        if let Some(ref path) = self.output {
            output::write_to_file(path, bytes)?;
            info!("hash saved to {}", path.display());
        } else if self.hex {
            output::print_hex(bytes);
        } else {
            output::write_binary_stdout(bytes)?;
        }

        if let Some(ref path) = self.ticket {
            let tss_ticket: TPMT_TK_HASHCHECK = ticket
                .try_into()
                .map_err(|e| anyhow::anyhow!("failed to convert ticket: {e:?}"))?;
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &tss_ticket as *const TPMT_TK_HASHCHECK as *const u8,
                    std::mem::size_of::<TPMT_TK_HASHCHECK>(),
                )
            };
            std::fs::write(path, bytes)
                .with_context(|| format!("writing ticket to {}", path.display()))?;
            info!("ticket saved to {}", path.display());
        }

        Ok(())
    }
}

fn read_input(path: &Option<PathBuf>) -> anyhow::Result<Vec<u8>> {
    match path {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display())),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).context("reading stdin")?;
            Ok(buf)
        }
    }
}
