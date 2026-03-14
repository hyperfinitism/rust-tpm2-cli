// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use log::info;
use tss_esapi::structures::{Public, Sensitive};
use tss_esapi::traits::UnMarshall;

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;

/// Load an external key into the TPM.
///
/// Wraps TPM2_LoadExternal: loads a key that was not created by the TPM
/// into a transient handle. This is useful for importing external public
/// keys for signature verification.
#[derive(Parser)]
pub struct LoadExternalCmd {
    /// Input file for the public portion (marshaled TPM2B_PUBLIC)
    #[arg(short = 'u', long = "public")]
    pub public: PathBuf,

    /// Input file for the private/sensitive portion (marshaled TPMT_SENSITIVE)
    #[arg(short = 'r', long = "private")]
    pub private: Option<PathBuf>,

    /// Hierarchy (o/owner, p/platform, e/endorsement, n/null)
    #[arg(short = 'a', long = "hierarchy", default_value = "n")]
    pub hierarchy: String,

    /// Output file for the loaded key context
    #[arg(short = 'c', long = "key-context")]
    pub key_context: Option<PathBuf>,

    /// Print name of the loaded object
    #[arg(short = 'n', long = "name")]
    pub name: Option<PathBuf>,
}

impl LoadExternalCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;
        let hierarchy = parse::parse_hierarchy(&self.hierarchy)?;

        let pub_data = std::fs::read(&self.public)
            .with_context(|| format!("reading public from {}", self.public.display()))?;
        let public = Public::unmarshall(&pub_data)
            .map_err(|e| anyhow::anyhow!("failed to unmarshal public: {e}"))?;

        let sensitive = match &self.private {
            Some(path) => {
                let priv_data = std::fs::read(path)
                    .with_context(|| format!("reading private from {}", path.display()))?;
                Sensitive::unmarshall(&priv_data)
                    .map_err(|e| anyhow::anyhow!("failed to unmarshal sensitive: {e}"))?
            }
            None => {
                // Load public-only (for verification keys etc).
                // Use an empty sensitive with matching type.
                return self.load_public_only(&mut ctx, public, hierarchy);
            }
        };

        let key_handle = ctx
            .execute_without_session(|ctx| ctx.load_external(sensitive, public, hierarchy))
            .context("TPM2_LoadExternal failed")?;

        self.save_context(&mut ctx, key_handle.into())?;
        info!("loaded external key");
        Ok(())
    }

    fn load_public_only(
        &self,
        ctx: &mut tss_esapi::Context,
        public: Public,
        hierarchy: tss_esapi::interface_types::resource_handles::Hierarchy,
    ) -> anyhow::Result<()> {
        let key_handle = ctx
            .execute_without_session(|ctx| ctx.load_external_public(public, hierarchy))
            .context("TPM2_LoadExternal (public only) failed")?;

        self.save_context(ctx, key_handle.into())?;
        info!("loaded external public key");
        Ok(())
    }

    fn save_context(
        &self,
        ctx: &mut tss_esapi::Context,
        handle: tss_esapi::handles::ObjectHandle,
    ) -> anyhow::Result<()> {
        if let Some(ref path) = self.key_context {
            let saved = ctx.context_save(handle).context("context_save failed")?;
            let json = serde_json::to_string(&saved)?;
            std::fs::write(path, json)
                .with_context(|| format!("writing context to {}", path.display()))?;
            info!("key context saved to {}", path.display());
        }

        if let Some(ref path) = self.name {
            let (_, name, _) = ctx
                .execute_without_session(|ctx| ctx.read_public(handle.into()))
                .context("TPM2_ReadPublic failed")?;
            std::fs::write(path, name.value())
                .with_context(|| format!("writing name to {}", path.display()))?;
            info!("name saved to {}", path.display());
        }

        Ok(())
    }
}
