// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Auth, Nonce};
use tss_esapi::structures::{Digest, PcrSelectionList, SymmetricDefinition};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_key_from_source, load_object_from_source};
use crate::parse;
#[derive(Parser)]
pub struct CreatePolicyCmd {
    /// Hash algorithm for the policy
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Symmetric algorithm for the trial session
    #[arg(long = "symmetric", default_value = "aes128cfb", value_parser = parse::parse_symmetric_definition)]
    pub symmetric: SymmetricDefinition,

    /// Bind the trial session to a loaded object (file:<path> or hex:<handle>)
    #[arg(long = "bind", value_parser = parse::parse_context_source)]
    pub bind: Option<ContextSource>,

    /// Authorization value for the bound object
    #[arg(long = "bind-auth", value_parser = parse::parse_auth, requires = "bind")]
    pub bind_auth: Option<Auth>,

    /// Key used to salt the trial session (file:<path> or hex:<handle>)
    #[arg(long = "tpm-key", value_parser = parse::parse_context_source)]
    pub tpm_key: Option<ContextSource>,

    /// Caller nonce as hexadecimal bytes
    #[arg(long = "nonce-caller", value_parser = parse::parse_hex_nonce)]
    pub nonce_caller: Option<Nonce>,

    /// Output file for the policy digest
    #[arg(short = 'L', long = "policy")]
    pub policy: PathBuf,

    /// Policy type: pcr
    #[arg(long = "policy-pcr", requires = "pcr_list")]
    pub policy_pcr: bool,

    /// PCR selection for --policy-pcr (e.g. sha256:0,1,2)
    #[arg(short = 'l', long = "pcr-list", value_parser = parse::parse_pcr_selection, requires = "policy_pcr")]
    pub pcr_list: Option<PcrSelectionList>,

    /// Expected PCR digest as hexadecimal bytes
    #[arg(short = 'f', long = "pcr-digest", value_parser = parse::parse_hex_digest, requires = "policy_pcr")]
    pub pcr_digest: Option<Digest>,
}

impl CreatePolicyCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let bind_handle = match &self.bind {
            Some(source) => Some(load_object_from_source(&mut ctx, source)?),
            None => None,
        };
        if let (Some(handle), Some(auth)) = (bind_handle, &self.bind_auth) {
            ctx.tr_set_auth(handle, auth.clone())
                .context("failed to set bound object authorization")?;
        }
        let tpm_key = match &self.tpm_key {
            Some(source) => Some(load_key_from_source(&mut ctx, source)?),
            None => None,
        };
        let session = ctx
            .start_auth_session(
                tpm_key,
                bind_handle,
                self.nonce_caller.clone(),
                SessionType::Trial,
                self.symmetric,
                self.hash_algorithm,
            )
            .context("failed to start trial session")?
            .ok_or_else(|| anyhow::anyhow!("no session returned"))?;

        let policy_session: tss_esapi::interface_types::session_handles::PolicySession = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected policy session"))?;

        if self.policy_pcr {
            let pcr_selection = self
                .pcr_list
                .as_ref()
                .expect("clap requires --pcr-list with --policy-pcr");
            ctx.policy_pcr(
                policy_session,
                self.pcr_digest.clone().unwrap_or_default(),
                pcr_selection.clone(),
            )
            .context("TPM2_PolicyPCR failed")?;
        }

        let digest = ctx
            .policy_get_digest(policy_session)
            .context("TPM2_PolicyGetDigest failed")?;

        std::fs::write(&self.policy, digest.as_bytes())
            .with_context(|| format!("writing policy to {}", self.policy.display()))?;
        info!(
            "policy digest saved to {} ({} bytes)",
            self.policy.display(),
            digest.as_bytes().len()
        );
        let obj_handle: ObjectHandle = SessionHandle::from(policy_session).into();
        ctx.flush_context(obj_handle)
            .context("failed to flush trial session")?;

        Ok(())
    }
}
