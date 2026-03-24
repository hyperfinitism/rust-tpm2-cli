// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Reset the dictionary attack lockout or configure DA parameters.
///
/// Wraps TPM2_DictionaryAttackLockReset and TPM2_DictionaryAttackParameters (raw FFI).
#[derive(Parser)]
pub struct DictionaryLockoutCmd {
    /// Auth value for the lockout hierarchy
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Reset the DA lockout counter
    #[arg(short = 'c', long = "clear-lockout")]
    pub clear_lockout: bool,

    /// Max number of authorization failures before lockout
    #[arg(long = "max-tries")]
    pub max_tries: Option<u32>,

    /// Lockout recovery time in seconds
    #[arg(long = "recovery-time")]
    pub recovery_time: Option<u32>,

    /// Lockout auth failure recovery time in seconds
    #[arg(long = "lockout-recovery-time")]
    pub lockout_recovery_time: Option<u32>,

    /// Setup mode: configure DA parameters (requires --max-tries, --recovery-time, --lockout-recovery-time)
    #[arg(short = 's', long = "setup-parameters")]
    pub setup_parameters: bool,
}

impl DictionaryLockoutCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(ESYS_TR_RH_LOCKOUT, auth.as_bytes())?;
        }

        if self.clear_lockout {
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
            let max_tries = self.max_tries.unwrap_or(32);
            let recovery_time = self.recovery_time.unwrap_or(10);
            let lockout_recovery = self.lockout_recovery_time.unwrap_or(10);

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
