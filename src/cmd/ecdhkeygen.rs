use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::parse_hex_u32;

/// Generate an ephemeral ECDH key pair and compute a shared secret.
///
/// Wraps TPM2_ECDH_KeyGen: creates an ephemeral key and computes the
/// shared secret Z point from the loaded ECC public key.
#[derive(Parser)]
pub struct EcdhKeygenCmd {
    /// ECC key context file path
    #[arg(short = 'c', long = "context", conflicts_with = "context_handle")]
    pub context: Option<PathBuf>,

    /// ECC key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "context-handle", value_parser = parse_hex_u32, conflicts_with = "context")]
    pub context_handle: Option<u32>,

    /// Output file for the ephemeral public point Q
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Output file for the shared secret Z point
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,
}

impl EcdhKeygenCmd {
    fn context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.context, self.context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!("exactly one of --context or --context-handle must be provided"),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context_source()?)?;

        let (z_point, pub_point) = ctx
            .execute_without_session(|ctx| ctx.ecdh_key_gen(key_handle))
            .context("TPM2_ECDH_KeyGen failed")?;

        // Serialize ECC points as x || y (raw concatenated coordinates).
        let pub_bytes = ecc_point_to_bytes(&pub_point);
        std::fs::write(&self.public, &pub_bytes)
            .with_context(|| format!("writing public point to {}", self.public.display()))?;
        info!("public point Q saved to {}", self.public.display());

        let z_bytes = ecc_point_to_bytes(&z_point);
        std::fs::write(&self.output, &z_bytes)
            .with_context(|| format!("writing shared secret to {}", self.output.display()))?;
        info!("shared secret Z saved to {}", self.output.display());

        Ok(())
    }
}

fn ecc_point_to_bytes(point: &tss_esapi::structures::EccPoint) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(point.x().value());
    out.extend_from_slice(point.y().value());
    out
}
