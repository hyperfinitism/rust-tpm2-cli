// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{AuthHandle, ObjectHandle, SessionHandle};
use tss_esapi::interface_types::reserved_handles::Provision;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::Auth;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::handle::load_nv_index;
use crate::parse;
use crate::session::{load_optional_auth_session, load_session_from_file, save_session_and_forget};
#[derive(Parser)]
pub struct NvUndefineSpaceSpecialCmd {
    /// NV index handle (hex, e.g. 0x01400001)
    #[arg(value_parser = parse::parse_nv_index)]
    pub nv_index: tss_esapi::handles::NvIndexTpmHandle,

    /// Authorization value for the platform hierarchy
    #[arg(short = 'P', long = "auth", value_parser = parse::parse_auth)]
    pub auth: Option<Auth>,

    /// Policy session file authorizing the NV index
    #[arg(short = 'S', long = "policy-session")]
    pub policy_session: PathBuf,

    /// Session context file for platform authorization
    #[arg(long = "platform-session")]
    pub platform_session: Option<PathBuf>,
}

impl NvUndefineSpaceSpecialCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;
        let nv_handle = load_nv_index(&mut ctx, self.nv_index)?;

        if let Some(auth) = &self.auth {
            ctx.tr_set_auth(AuthHandle::Platform.into(), auth.clone())
                .context("failed to set platform authorization")?;
        }

        let session = load_session_from_file(&mut ctx, &self.policy_session, SessionType::Policy)?;
        let policy_session = session
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected a policy session"))?;
        let platform_session =
            load_optional_auth_session(&mut ctx, self.platform_session.as_deref())?;
        ctx.set_sessions((
            Some(AuthSession::PolicySession(policy_session)),
            Some(platform_session),
            None,
        ));
        ctx.nv_undefine_space_special(Provision::Platform, nv_handle)
            .context("TPM2_NV_UndefineSpaceSpecial failed")?;
        ctx.clear_sessions();

        info!("NV index 0x{:08x} undefined", u32::from(self.nv_index));
        let handle: ObjectHandle = SessionHandle::from(policy_session).into();
        save_session_and_forget(ctx, handle, &self.policy_session)
    }
}
