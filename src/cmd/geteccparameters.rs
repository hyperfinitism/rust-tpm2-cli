use clap::Parser;
use serde_json::json;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::raw_esys::RawEsysContext;

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
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;

        let curve_id = parse_ecc_curve(&self.curve)?;

        unsafe {
            let mut params: *mut TPMS_ALGORITHM_DETAIL_ECC = std::ptr::null_mut();
            let rc = Esys_ECC_Parameters(
                raw.ptr(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                curve_id,
                &mut params,
            );
            if rc != 0 {
                anyhow::bail!("Esys_ECC_Parameters failed: 0x{rc:08x}");
            }

            let p = &*params;
            let output = json!({
                "curve_id": format!("0x{:04x}", p.curveID),
                "key_size": p.keySize,
                "kdf_scheme": format!("0x{:04x}", p.kdf.scheme),
                "sign_scheme": format!("0x{:04x}", p.sign.scheme),
                "p": hex::encode(&p.p.buffer[..p.p.size as usize]),
                "a": hex::encode(&p.a.buffer[..p.a.size as usize]),
                "b": hex::encode(&p.b.buffer[..p.b.size as usize]),
                "gX": hex::encode(&p.gX.buffer[..p.gX.size as usize]),
                "gY": hex::encode(&p.gY.buffer[..p.gY.size as usize]),
                "n": hex::encode(&p.n.buffer[..p.n.size as usize]),
                "h": hex::encode(&p.h.buffer[..p.h.size as usize]),
            });

            Esys_Free(params as *mut _);

            println!("{}", serde_json::to_string_pretty(&output)?);
        }

        Ok(())
    }
}

fn parse_ecc_curve(s: &str) -> anyhow::Result<u16> {
    use tss_esapi::constants::tss::*;
    match s.to_lowercase().as_str() {
        "ecc192" | "nistp192" => Ok(TPM2_ECC_NIST_P192),
        "ecc224" | "nistp224" => Ok(TPM2_ECC_NIST_P224),
        "ecc256" | "nistp256" => Ok(TPM2_ECC_NIST_P256),
        "ecc384" | "nistp384" => Ok(TPM2_ECC_NIST_P384),
        "ecc521" | "nistp521" => Ok(TPM2_ECC_NIST_P521),
        "bnp256" => Ok(TPM2_ECC_BN_P256),
        "bnp638" => Ok(TPM2_ECC_BN_P638),
        "sm2p256" | "sm2" => Ok(TPM2_ECC_SM2_P256),
        _ => anyhow::bail!("unsupported ECC curve: {s}"),
    }
}
