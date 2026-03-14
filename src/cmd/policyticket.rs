use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::raw_esys::RawEsysContext;

/// Include a policy ticket to satisfy a prior policy assertion.
///
/// Wraps TPM2_PolicyTicket (raw FFI).
#[derive(Parser)]
pub struct PolicyTicketCmd {
    /// Policy session context file
    #[arg(short = 'S', long = "session")]
    pub session: PathBuf,

    /// Timeout value (hex bytes)
    #[arg(long = "timeout")]
    pub timeout: Option<String>,

    /// cpHash for the command being authorized (hex)
    #[arg(long = "cphash")]
    pub cphash: Option<String>,

    /// Policy reference (hex)
    #[arg(long = "policy-ref")]
    pub policy_ref: Option<String>,

    /// Key name (hex)
    #[arg(short = 'n', long = "name")]
    pub name: String,

    /// Ticket file (binary)
    #[arg(short = 't', long = "ticket")]
    pub ticket: PathBuf,
}

impl PolicyTicketCmd {
    #[allow(clippy::field_reassign_with_default)]
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let session_handle = raw.context_load(
            self.session
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid session path"))?,
        )?;

        let mut timeout = TPM2B_TIMEOUT::default();
        if let Some(ref t) = self.timeout {
            let bytes = hex::decode(t).context("invalid timeout hex")?;
            timeout.size = bytes.len() as u16;
            timeout.buffer[..bytes.len()].copy_from_slice(&bytes);
        }

        let mut cp_hash_a = TPM2B_DIGEST::default();
        if let Some(ref h) = self.cphash {
            let bytes = hex::decode(h).context("invalid cphash hex")?;
            cp_hash_a.size = bytes.len() as u16;
            cp_hash_a.buffer[..bytes.len()].copy_from_slice(&bytes);
        }

        let mut policy_ref = TPM2B_NONCE::default();
        if let Some(ref r) = self.policy_ref {
            let bytes = hex::decode(r).context("invalid policy-ref hex")?;
            policy_ref.size = bytes.len() as u16;
            policy_ref.buffer[..bytes.len()].copy_from_slice(&bytes);
        }

        let name_bytes = hex::decode(&self.name).context("invalid name hex")?;
        let mut auth_name = TPM2B_NAME::default();
        auth_name.size = name_bytes.len() as u16;
        auth_name.name[..name_bytes.len()].copy_from_slice(&name_bytes);

        // Read ticket from file
        let ticket_data = std::fs::read(&self.ticket)
            .with_context(|| format!("reading ticket from {}", self.ticket.display()))?;
        if ticket_data.len() < std::mem::size_of::<TPMT_TK_AUTH>() {
            anyhow::bail!("ticket file too small");
        }
        let ticket: TPMT_TK_AUTH =
            unsafe { std::ptr::read(ticket_data.as_ptr() as *const TPMT_TK_AUTH) };

        unsafe {
            let rc = Esys_PolicyTicket(
                raw.ptr(),
                session_handle,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &timeout,
                &cp_hash_a,
                &policy_ref,
                &auth_name,
                &ticket,
            );
            if rc != 0 {
                anyhow::bail!("Esys_PolicyTicket failed: 0x{rc:08x}");
            }
        }

        raw.context_save_to_file(session_handle, &self.session)?;
        info!("policy ticket asserted");
        Ok(())
    }
}
