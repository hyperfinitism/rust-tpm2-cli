// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use serde_json::json;
use tss_esapi::tss2_esys::{TPMT_ECC_SCHEME, TPMT_KDF_SCHEME};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;

/// Get the ECC curve parameters for a given curve.
///
/// Wraps TPM2_ECC_Parameters (raw FFI).
#[derive(Parser)]
pub struct GetEccParametersCmd {
    /// ECC curve (ecc256, ecc384, ecc521, etc.)
    #[arg()]
    pub curve: String,
}

impl GetEccParametersCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_deref())?;

        let curve = parse::parse_ecc_curve(&self.curve).map_err(anyhow::Error::msg)?;
        let params = ctx.ecc_parameters(curve).map_err(|e| anyhow::anyhow!(e))?;
        let curve_id: u16 = params.curve_id().into();
        let kdf: TPMT_KDF_SCHEME = (*params.kdf()).into();
        let sign: TPMT_ECC_SCHEME = (*params.sign()).into();

        let output = json!({
            "curve_id": format!("0x{curve_id:04x}"),
            "key_size": params.key_size(),
            "kdf_scheme": format!("0x{:04x}", kdf.scheme),
            "sign_scheme": format!("0x{:04x}", sign.scheme),
            "p": hex::encode(params.p().as_bytes()),
            "a": hex::encode(params.a().as_bytes()),
            "b": hex::encode(params.b().as_bytes()),
            "gX": hex::encode(params.g_x().as_bytes()),
            "gY": hex::encode(params.g_y().as_bytes()),
            "n": hex::encode(params.n().as_bytes()),
            "h": hex::encode(params.h().as_bytes()),
        });

        println!("{}", serde_json::to_string_pretty(&output)?);

        Ok(())
    }
}
