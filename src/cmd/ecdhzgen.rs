// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::structures::{EccParameter, EccPoint};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source};
use crate::parse::{self, parse_hex_u32};
use crate::session::execute_with_optional_session;

/// Compute a shared secret from an ECC key and a public point.
///
/// Wraps TPM2_ECDH_ZGen: uses the private portion of the loaded ECC
/// key and the caller-supplied public point to compute the shared Z.
#[derive(Parser)]
pub struct EcdhZgenCmd {
    /// ECC key context file path
    #[arg(
        short = 'c',
        long = "key-context",
        conflicts_with = "key_context_handle"
    )]
    pub key_context: Option<PathBuf>,

    /// ECC key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "key-context-handle", value_parser = parse_hex_u32, conflicts_with = "key_context")]
    pub key_context_handle: Option<u32>,

    /// Auth value for the key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Input file containing the public point (raw x||y bytes)
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Output file for the shared secret Z point (raw x||y bytes)
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl EcdhZgenCmd {
    fn context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.key_context, self.key_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --key-context or --key-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_key_from_source(&mut ctx, &self.context_source()?)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            ctx.tr_set_auth(key_handle.into(), auth)
                .context("tr_set_auth failed")?;
        }

        let point_data = std::fs::read(&self.public)
            .with_context(|| format!("reading public point from {}", self.public.display()))?;
        if point_data.len() < 2 {
            bail!("public point file too short");
        }
        let half = point_data.len() / 2;
        let x = EccParameter::try_from(&point_data[..half])
            .map_err(|e| anyhow::anyhow!("invalid x coordinate: {e}"))?;
        let y = EccParameter::try_from(&point_data[half..])
            .map_err(|e| anyhow::anyhow!("invalid y coordinate: {e}"))?;
        let in_point = EccPoint::new(x, y);

        let session_path = self.session.as_deref();
        let z_point = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.ecdh_z_gen(key_handle, in_point.clone())
        })
        .context("TPM2_ECDH_ZGen failed")?;

        let mut z_bytes = Vec::new();
        z_bytes.extend_from_slice(z_point.x().value());
        z_bytes.extend_from_slice(z_point.y().value());

        std::fs::write(&self.output, &z_bytes)
            .with_context(|| format!("writing Z point to {}", self.output.display()))?;
        info!("shared secret Z saved to {}", self.output.display());

        Ok(())
    }
}
