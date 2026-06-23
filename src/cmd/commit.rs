// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{Auth, EccParameter, EccPoint, SensitiveData};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::ContextSource;
use crate::handle::load_key_from_source;
use crate::parse::{self, parse_context_source};

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
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

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
        let mut ctx = create_context(global.tcti.as_deref())?;
        let sign_handle = load_key_from_source(&mut ctx, &self.context)?;

        if let Some(ref auth) = self.auth {
            ctx.tr_set_auth(sign_handle.into(), auth.clone())
                .context("failed to set signing key auth")?;
        }

        let p1 = p1
            .map(|data| bytes_to_ecc_point(&data))
            .transpose()
            .map_err(|e| anyhow::anyhow!("p1 parameter: {e}"))?;
        let s2 = s2
            .map(SensitiveData::try_from)
            .transpose()
            .map_err(|e| anyhow::anyhow!("s2 parameter: {e}"))?;
        let y2 = y2
            .map(EccParameter::try_from)
            .transpose()
            .map_err(|e| anyhow::anyhow!("y2 parameter: {e}"))?;

        ctx.set_sessions((Some(AuthSession::Password), None, None));
        let result = ctx
            .commit(sign_handle, p1, s2, y2)
            .map_err(|e| anyhow::anyhow!(e));
        ctx.clear_sessions();
        let (k, l, e, counter) = result.context("TPM2_Commit failed")?;

        if let Some(ref path) = self.eccpoint_k {
            std::fs::write(path, ecc_point_to_bytes(&k))
                .with_context(|| format!("writing K to {}", path.display()))?;
            info!("ECC point K saved to {}", path.display());
        }

        if let Some(ref path) = self.eccpoint_l {
            std::fs::write(path, ecc_point_to_bytes(&l))
                .with_context(|| format!("writing L to {}", path.display()))?;
            info!("ECC point L saved to {}", path.display());
        }

        if let Some(ref path) = self.eccpoint_e {
            std::fs::write(path, ecc_point_to_bytes(&e))
                .with_context(|| format!("writing E to {}", path.display()))?;
            info!("ECC point E saved to {}", path.display());
        }

        if let Some(ref path) = self.counter {
            std::fs::write(path, counter.to_le_bytes())
                .with_context(|| format!("writing counter to {}", path.display()))?;
            info!("counter saved to {}", path.display());
        }

        info!("commit succeeded (counter={counter})");
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

fn bytes_to_ecc_point(data: &[u8]) -> tss_esapi::Result<EccPoint> {
    let half = data.len() / 2;
    let x = EccParameter::try_from(data[..half].to_vec())?;
    let y = EccParameter::try_from(data[half..].to_vec())?;
    Ok(EccPoint::new(x, y))
}

fn ecc_point_to_bytes(point: &EccPoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(point.x().len() + point.y().len());
    out.extend_from_slice(point.x().as_bytes());
    out.extend_from_slice(point.y().as_bytes());
    out
}
