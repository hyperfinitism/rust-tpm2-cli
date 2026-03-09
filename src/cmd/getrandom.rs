use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::{info, warn};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::output;
use crate::session::execute_with_optional_session;

/// Get random bytes from the TPM.
#[derive(Parser)]
pub struct GetRandomCmd {
    /// Number of random bytes to retrieve
    pub num_bytes: u16,

    /// Output file path (default: stdout)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Print output as a hex string
    #[arg(long)]
    pub hex: bool,

    /// Bypass the TPM max-digest size check
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl GetRandomCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let num_bytes = self.num_bytes;
        let session_path = self.session.as_deref();
        let random = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.get_random(num_bytes.into())
        })
        .context("TPM2_GetRandom failed")?;

        let bytes = random.value();
        if bytes.len() < num_bytes as usize {
            warn!(
                "TPM returned fewer bytes than requested: expected {}, got {}",
                num_bytes,
                bytes.len(),
            );
        }

        if let Some(ref path) = self.output {
            output::write_to_file(path, bytes)?;
            info!("wrote {} bytes to {}", bytes.len(), path.display());
        } else if self.hex {
            output::print_hex(bytes);
        } else {
            output::write_binary_stdout(bytes)?;
        }

        Ok(())
    }
}
