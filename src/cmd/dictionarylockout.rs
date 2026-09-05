// SPDX-License-Identifier: Apache-2.0

use clap::{ArgGroup, Parser};
use log::info;
use tss_esapi::tss2_esys::*;

use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;
#[derive(Parser)]
#[command(group(
    ArgGroup::new("action")
        .required(true)
        .multiple(false)
        .args(["clear_lockout", "setup_parameters"])
))]
pub struct DictionaryLockoutCmd {
    /// Authorization value for the lockout hierarchy
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Reset the DA lockout counter
    #[arg(short = 'c', long = "clear-lockout")]
    pub clear_lockout: bool,

    /// Max number of authorization failures before lockout
    #[arg(long = "max-tries", default_value = "32")]
    pub max_tries: u32,

    /// Lockout recovery time in seconds
    #[arg(long = "recovery-time", default_value = "10")]
    pub recovery_time: u32,

    /// Lockout auth failure recovery time in seconds
    #[arg(long = "lockout-recovery-time", default_value = "10")]
    pub lockout_recovery_time: u32,

    /// Setup mode: configure DA parameters (requires --max-tries, --recovery-time, --lockout-recovery-time)
    #[arg(short = 's', long = "setup-parameters")]
    pub setup_parameters: bool,
}

impl DictionaryLockoutCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_ref())?;

        if let Some(ref auth) = self.auth {
            raw.set_auth(ESYS_TR_RH_LOCKOUT, auth.as_bytes())?;
        }

        if self.clear_lockout {
            // Raw ESYS fallback: rust-tss-esapi does not expose TPM2_DictionaryAttackLockReset.
            unsafe {
                let rc = Esys_DictionaryAttackLockReset(
                    raw.ptr(),
                    ESYS_TR_RH_LOCKOUT,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                );
                if rc != 0 {
                    anyhow::bail!("Esys_DictionaryAttackLockReset failed: 0x{rc:08x}");
                }
            }
            info!("DA lockout counter cleared");
        }

        if self.setup_parameters {
            let max_tries = self.max_tries;
            let recovery_time = self.recovery_time;
            let lockout_recovery = self.lockout_recovery_time;

            // Raw ESYS fallback: rust-tss-esapi does not expose TPM2_DictionaryAttackParameters.
            unsafe {
                let rc = Esys_DictionaryAttackParameters(
                    raw.ptr(),
                    ESYS_TR_RH_LOCKOUT,
                    ESYS_TR_PASSWORD,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    max_tries,
                    recovery_time,
                    lockout_recovery,
                );
                if rc != 0 {
                    anyhow::bail!("Esys_DictionaryAttackParameters failed: 0x{rc:08x}");
                }
            }
            info!(
                "DA parameters set: max_tries={max_tries}, recovery_time={recovery_time}, lockout_recovery={lockout_recovery}"
            );
        }

        Ok(())
    }
}
