// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use log::info;
use tss_esapi::structures::DigestValues;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
use crate::session::execute_with_optional_session;

/// Extend a PCR register with one or more digests.
///
/// Format: `<pcr_index>:<alg>=<hex_digest>[+<alg>=<hex_digest>...]`
///
/// Example: `tpm2 pcrextend 0:sha256=<64-char-hex>`
#[derive(Parser)]
pub struct PcrExtendCmd {
    /// PCR extension specification
    pub extend_spec: String,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl PcrExtendCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let (pcr_index_str, digests_str) = self
            .extend_spec
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("expected format <pcr>:<alg>=<hex>"))?;

        let pcr_index: u8 = pcr_index_str.parse().context("invalid PCR index")?;
        let pcr_handle = pcr_index_to_handle(pcr_index)?;

        let mut digest_values = DigestValues::new();

        for part in digests_str.split('+') {
            let (alg_str, hex_str) = part
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("expected <alg>=<hex> in '{part}'"))?;

            let alg = parse::parse_hashing_algorithm(alg_str)?;
            let bytes =
                hex::decode(hex_str).with_context(|| format!("invalid hex in '{hex_str}'"))?;
            let digest = bytes
                .try_into()
                .map_err(|e: tss_esapi::Error| anyhow::anyhow!("{e}"))?;
            digest_values.set(alg, digest);
        }

        let session_path = self.session.as_deref();
        execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.pcr_extend(pcr_handle, digest_values.clone())
        })
        .context("TPM2_PCR_Extend failed")?;

        info!("PCR {pcr_index} extended");
        Ok(())
    }
}

fn pcr_index_to_handle(idx: u8) -> anyhow::Result<tss_esapi::handles::PcrHandle> {
    use tss_esapi::handles::PcrHandle;
    let handle = match idx {
        0 => PcrHandle::Pcr0,
        1 => PcrHandle::Pcr1,
        2 => PcrHandle::Pcr2,
        3 => PcrHandle::Pcr3,
        4 => PcrHandle::Pcr4,
        5 => PcrHandle::Pcr5,
        6 => PcrHandle::Pcr6,
        7 => PcrHandle::Pcr7,
        8 => PcrHandle::Pcr8,
        9 => PcrHandle::Pcr9,
        10 => PcrHandle::Pcr10,
        11 => PcrHandle::Pcr11,
        12 => PcrHandle::Pcr12,
        13 => PcrHandle::Pcr13,
        14 => PcrHandle::Pcr14,
        15 => PcrHandle::Pcr15,
        16 => PcrHandle::Pcr16,
        17 => PcrHandle::Pcr17,
        18 => PcrHandle::Pcr18,
        19 => PcrHandle::Pcr19,
        20 => PcrHandle::Pcr20,
        21 => PcrHandle::Pcr21,
        22 => PcrHandle::Pcr22,
        23 => PcrHandle::Pcr23,
        24 => PcrHandle::Pcr24,
        25 => PcrHandle::Pcr25,
        26 => PcrHandle::Pcr26,
        27 => PcrHandle::Pcr27,
        28 => PcrHandle::Pcr28,
        29 => PcrHandle::Pcr29,
        30 => PcrHandle::Pcr30,
        31 => PcrHandle::Pcr31,
        _ => bail!("invalid PCR index: {idx}"),
    };
    Ok(handle)
}
