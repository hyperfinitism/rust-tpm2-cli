// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::handle::ContextSource;
use crate::parse::parse_context_source;
use crate::raw_esys;

/// Perform the first part of an ECC anonymous signing operation.
///
/// Wraps TPM2_Commit: performs point multiplications on the provided
/// points and returns intermediate signing values.  The signing key
/// must use the ECDAA scheme.
#[derive(Parser)]
pub struct CommitCmd {
    /// Signing key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "context", value_parser = parse_context_source)]
    pub context: ContextSource,

    /// Auth value for the signing key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// ECC point P1 input file (optional)
    #[arg(long = "eccpoint-P")]
    pub eccpoint_p: Option<PathBuf>,

    /// Basepoint x-coordinate data file (optional, s2 parameter)
    #[arg()]
    pub basepoint_x: Option<PathBuf>,

    /// Basepoint y-coordinate file (optional, y2 parameter)
    #[arg(long = "basepoint-y")]
    pub basepoint_y: Option<PathBuf>,

    /// Output ECC point K file
    #[arg(long = "eccpoint-K")]
    pub eccpoint_k: Option<PathBuf>,

    /// Output ECC point L file
    #[arg(long = "eccpoint-L")]
    pub eccpoint_l: Option<PathBuf>,

    /// Output ECC point E file
    #[arg(short = 'u', long = "public")]
    pub eccpoint_e: Option<PathBuf>,

    /// Output counter file
    #[arg(short = 't', long = "counter")]
    pub counter: Option<PathBuf>,
}

impl CommitCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let p1 = read_opt_file(&self.eccpoint_p)?;
        let s2 = read_opt_file(&self.basepoint_x)?;
        let y2 = read_opt_file(&self.basepoint_y)?;

        let result = raw_esys::commit(
            global.tcti.as_deref(),
            &self.context,
            self.auth.as_deref(),
            p1.as_deref(),
            s2.as_deref(),
            y2.as_deref(),
        )
        .context("TPM2_Commit failed")?;

        if let Some(ref path) = self.eccpoint_k {
            std::fs::write(path, &result.k)
                .with_context(|| format!("writing K to {}", path.display()))?;
            info!("ECC point K saved to {}", path.display());
        }

        if let Some(ref path) = self.eccpoint_l {
            std::fs::write(path, &result.l)
                .with_context(|| format!("writing L to {}", path.display()))?;
            info!("ECC point L saved to {}", path.display());
        }

        if let Some(ref path) = self.eccpoint_e {
            std::fs::write(path, &result.e)
                .with_context(|| format!("writing E to {}", path.display()))?;
            info!("ECC point E saved to {}", path.display());
        }

        if let Some(ref path) = self.counter {
            std::fs::write(path, result.counter.to_le_bytes())
                .with_context(|| format!("writing counter to {}", path.display()))?;
            info!("counter saved to {}", path.display());
        }

        info!("commit succeeded (counter={})", result.counter);
        Ok(())
    }
}

fn read_opt_file(path: &Option<PathBuf>) -> anyhow::Result<Option<Vec<u8>>> {
    match path {
        Some(p) => {
            let data = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
            Ok(Some(data))
        }
        None => Ok(None),
    }
}
