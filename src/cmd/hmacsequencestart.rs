// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::{ContextSource, load_object_from_source};
use crate::parse::{self, parse_context_source};
use crate::session::execute_with_optional_session;

/// Start an HMAC sequence on the TPM.
///
/// Wraps TPM2_HMAC_Start: begins an incremental HMAC computation using the
/// specified key.  The returned sequence handle is saved to a context file
/// for use with `sequenceupdate` and `sequencecomplete`.
#[derive(Parser)]
pub struct HmacSequenceStartCmd {
    /// HMAC key context (file:<path> or hex:<handle>)
    #[arg(short = 'c', long = "key-context", value_parser = parse_context_source)]
    pub key_context: ContextSource,

    /// Auth value for the key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Hash algorithm (default: sha256)
    #[arg(short = 'g', long = "hash-algorithm", default_value = "sha256")]
    pub hash_algorithm: String,

    /// Output file for the sequence context
    #[arg(short = 'o', long = "output")]
    pub output: PathBuf,

    /// Session context file for authorization
    #[arg(short = 'S', long = "session")]
    pub session: Option<PathBuf>,
}

impl HmacSequenceStartCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let key_handle = load_object_from_source(&mut ctx, &self.key_context)?;
        let hash_alg = parse::parse_hashing_algorithm(&self.hash_algorithm)?;

        let auth_value = match &self.auth {
            Some(a) => {
                let auth = parse::parse_auth(a)?;
                ctx.tr_set_auth(key_handle, auth.clone())
                    .context("tr_set_auth failed")?;
                Some(auth)
            }
            None => None,
        };

        let session_path = self.session.as_deref();
        let seq_handle = execute_with_optional_session(&mut ctx, session_path, |ctx| {
            ctx.hmac_sequence_start(key_handle, hash_alg, auth_value.clone())
        })
        .context("TPM2_HMAC_Start failed")?;

        // Save the sequence handle context.
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
