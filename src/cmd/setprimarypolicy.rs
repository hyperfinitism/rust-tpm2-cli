use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::parse;
use crate::raw_esys::RawEsysContext;

/// Set the authorization policy for a hierarchy.
///
/// Wraps TPM2_SetPrimaryPolicy (raw FFI).
#[derive(Parser)]
pub struct SetPrimaryPolicyCmd {
    /// Hierarchy (o/owner, e/endorsement, p/platform, l/lockout)
    #[arg(short = 'C', long = "hierarchy")]
    pub hierarchy: String,

    /// Auth value
    #[arg(short = 'P', long = "auth")]
    pub auth: Option<String>,

    /// Policy digest file
    #[arg(short = 'L', long = "policy")]
    pub policy: PathBuf,

    /// Hash algorithm used for the policy (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,
}

impl SetPrimaryPolicyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let auth_handle = RawEsysContext::resolve_hierarchy(&self.hierarchy)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(auth_handle, auth.value())?;
        }

        let policy_data = std::fs::read(&self.policy)
            .with_context(|| format!("reading policy from {}", self.policy.display()))?;

        let mut auth_policy = TPM2B_DIGEST::default();
        let len = policy_data.len().min(auth_policy.buffer.len());
        auth_policy.size = len as u16;
        auth_policy.buffer[..len].copy_from_slice(&policy_data[..len]);

        let hash_alg: u16 = match self.hash_algorithm.to_lowercase().as_str() {
            "sha1" => TPM2_ALG_SHA1,
            "sha256" => TPM2_ALG_SHA256,
            "sha384" => TPM2_ALG_SHA384,
            "sha512" => TPM2_ALG_SHA512,
            _ => anyhow::bail!("unknown hash algorithm: {}", self.hash_algorithm),
        };

        unsafe {
            let rc = Esys_SetPrimaryPolicy(
                raw.ptr(),
                auth_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &auth_policy,
                hash_alg,
            );
            if rc != 0 {
                anyhow::bail!("Esys_SetPrimaryPolicy failed: 0x{rc:08x}");
            }
        }

        info!("primary policy set for hierarchy {}", self.hierarchy);
        Ok(())
    }
}
