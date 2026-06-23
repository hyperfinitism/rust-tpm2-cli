// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use serde_json::json;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::tss2_esys::{TPMT_ECC_SCHEME, TPMT_KDF_SCHEME};

use crate::cli::GlobalOpts;
use crate::context::create_context;
use crate::parse;
#[derive(Parser)]
pub struct GetEccParametersCmd {
    /// ECC curve (ecc256, ecc384, ecc521, etc.)
    #[arg(value_parser = parse::parse_ecc_curve)]
    pub curve: EccCurve,
}

impl GetEccParametersCmd {
    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut ctx = create_context(global.tcti.as_ref())?;

        let params = ctx
            .ecc_parameters(self.curve)
            .map_err(|e| anyhow::anyhow!(e))?;
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
