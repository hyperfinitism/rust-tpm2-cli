// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::output;
#[derive(Parser)]
pub struct SendCmd {
    /// Input file containing the raw TPM command bytes
    #[arg(short = 'i', long = "input")]
    pub input: PathBuf,

    /// Output file for the raw TPM response
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    /// TPM device path (default: extracted from TCTI or /dev/tpm0)
    #[arg(short = 'd', long = "device")]
    pub device: Option<PathBuf>,
}

impl SendCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let cmd_bytes = std::fs::read(&self.input)
            .with_context(|| format!("reading command from {}", self.input.display()))?;

        let device_path = match &self.device {
            Some(d) => d.clone(),
            None => PathBuf::from(crate::tcti::extract_device_path(global.tcti.as_ref())),
        };
        let mut dev = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device_path)
            .with_context(|| format!("opening TPM device {}", device_path.display()))?;

        dev.write_all(&cmd_bytes)
            .context("writing command to TPM device")?;
        let mut header = [0u8; 10];
        dev.read_exact(&mut header)
            .context("reading TPM response header")?;

        let response_size =
            u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut response = vec![0u8; response_size];
        response[..10].copy_from_slice(&header);
        if response_size > 10 {
            dev.read_exact(&mut response[10..])
                .context("reading TPM response body")?;
        }

        if let Some(ref path) = self.output {
            output::write_to_file(path, &response)?;
            info!(
                "response ({} bytes) saved to {}",
                response.len(),
                path.display()
            );
        } else {
            output::print_hex(&response);
        }

        Ok(())
    }
}
