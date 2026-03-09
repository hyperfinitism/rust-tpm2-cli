use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::handles::PcrHandle;

use crate::cli::GlobalOpts;
use crate::context::create_context;

/// Reset a PCR to its default value.
///
/// Wraps TPM2_PCR_Reset. Only resettable PCRs (e.g. PCR 16, debug PCR)
/// can be reset.
#[derive(Parser)]
pub struct PcrResetCmd {
    /// PCR index to reset (e.g. 16)
    #[arg()]
    pub pcr_index: u8,
}

impl PcrResetCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let pcr_handle = pcr_index_to_handle(self.pcr_index)?;

        ctx.execute_with_nullauth_session(|ctx| ctx.pcr_reset(pcr_handle))
            .context("TPM2_PCR_Reset failed")?;

        info!("PCR {} reset", self.pcr_index);
        Ok(())
    }
}

fn pcr_index_to_handle(idx: u8) -> anyhow::Result<PcrHandle> {
    match idx {
        0 => Ok(PcrHandle::Pcr0),
        1 => Ok(PcrHandle::Pcr1),
        2 => Ok(PcrHandle::Pcr2),
        3 => Ok(PcrHandle::Pcr3),
        4 => Ok(PcrHandle::Pcr4),
        5 => Ok(PcrHandle::Pcr5),
        6 => Ok(PcrHandle::Pcr6),
        7 => Ok(PcrHandle::Pcr7),
        8 => Ok(PcrHandle::Pcr8),
        9 => Ok(PcrHandle::Pcr9),
        10 => Ok(PcrHandle::Pcr10),
        11 => Ok(PcrHandle::Pcr11),
        12 => Ok(PcrHandle::Pcr12),
        13 => Ok(PcrHandle::Pcr13),
        14 => Ok(PcrHandle::Pcr14),
        15 => Ok(PcrHandle::Pcr15),
        16 => Ok(PcrHandle::Pcr16),
        17 => Ok(PcrHandle::Pcr17),
        18 => Ok(PcrHandle::Pcr18),
        19 => Ok(PcrHandle::Pcr19),
        20 => Ok(PcrHandle::Pcr20),
        21 => Ok(PcrHandle::Pcr21),
        22 => Ok(PcrHandle::Pcr22),
        23 => Ok(PcrHandle::Pcr23),
        _ => anyhow::bail!("PCR index {idx} out of range (0-23)"),
    }
}
