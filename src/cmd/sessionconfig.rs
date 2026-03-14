// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::attributes::SessionAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{ObjectHandle, SessionHandle};
use tss_esapi::tss2_esys::TPMA_SESSION;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::session::load_session_from_file;

const DECRYPT_BIT: TPMA_SESSION = 1 << 5;
const ENCRYPT_BIT: TPMA_SESSION = 1 << 6;
const AUDIT_BIT: TPMA_SESSION = 1 << 7;

/// Configure session attributes (encrypt, decrypt, audit, etc.).
///
/// Modifies the session attributes and saves the session back.
#[derive(Parser)]
pub struct SessionConfigCmd {
    /// Session context file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Enable command encryption
    #[arg(long = "enable-encrypt")]
    pub enable_encrypt: bool,

    /// Enable command decryption
    #[arg(long = "enable-decrypt")]
    pub enable_decrypt: bool,

    /// Enable audit
    #[arg(long = "enable-audit")]
    pub enable_audit: bool,

    /// Disable command encryption
    #[arg(long = "disable-encrypt")]
    pub disable_encrypt: bool,

    /// Disable command decryption
    #[arg(long = "disable-decrypt")]
    pub disable_decrypt: bool,

    /// Disable audit
    #[arg(long = "disable-audit")]
    pub disable_audit: bool,
}

impl SessionConfigCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        // Load the session.
        let session = load_session_from_file(&mut ctx, &self.session, SessionType::Hmac)?;

        let session_handle: SessionHandle = session.into();

        // Get current attributes as raw TPMA_SESSION.
        let current_attrs = ctx
            .tr_sess_get_attributes(session)
            .context("failed to get session attributes")?;
        let mut raw: TPMA_SESSION = current_attrs.into();

        // Modify based on flags using named bit constants.
        if self.enable_encrypt {
            raw |= ENCRYPT_BIT;
        }
        if self.enable_decrypt {
            raw |= DECRYPT_BIT;
        }
        if self.enable_audit {
            raw |= AUDIT_BIT;
        }
        if self.disable_encrypt {
            raw &= !ENCRYPT_BIT;
        }
        if self.disable_decrypt {
            raw &= !DECRYPT_BIT;
        }
        if self.disable_audit {
            raw &= !AUDIT_BIT;
        }

        let (attrs, mask) = SessionAttributesBuilder::new()
            .with_decrypt(raw & DECRYPT_BIT != 0)
            .with_encrypt(raw & ENCRYPT_BIT != 0)
            .with_audit(raw & AUDIT_BIT != 0)
            .build();

        ctx.tr_sess_set_attributes(session, attrs, mask)
            .context("failed to set session attributes")?;

        info!("session attributes updated");

        // Save back.
        let obj_handle: ObjectHandle = session_handle.into();
        crate::session::save_session_and_forget(ctx, obj_handle, &self.session)?;

        Ok(())
    }
}
