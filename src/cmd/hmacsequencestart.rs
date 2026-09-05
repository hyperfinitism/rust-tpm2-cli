// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;
#[derive(Parser)]
pub struct HmacSequenceStartCmd {
    /// HMAC key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Authorization value for the key
    #[arg(short = 'p', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Authorization value for the new sequence
    #[arg(long = "sequence-auth", value_parser = parse::parse_auth)]
    pub sequence_auth: Option<Auth>,

    /// Hash algorithm
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256", value_parser = parse::parse_hashing_algorithm)]
    pub hash_algorithm: HashingAlgorithm,

    /// Output file for the sequence context
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl HmacSequenceStartCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let key_handle = load_object_from_source(&mut ctx, &self.key_context)?;
        let hash_alg = self.hash_algorithm;

        let auth_value = self.auth.clone();
        if let Some(ref auth) = auth_value {
            ctx.tr_set_auth(key_handle, auth.clone())
                .context("tr_set_auth failed")?;
        }

        let session_path = self.session.as_deref();
        let seq_handle = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.hmac_sequence_start(key_handle, hash_alg, self.sequence_auth.clone())
        })
        .context("TPM2_HMAC_Start failed")?;
        let saved = ctx
            .context_save(seq_handle)
            .context("context_save failed")?;
        let json = serde_json::to_string(&saved)?;
        std::fs::write(&self.output, json)?;

        info!(
            "HMAC sequence started, context saved to {}",
            self.output.display()
        );
        Ok(())
    }
}
