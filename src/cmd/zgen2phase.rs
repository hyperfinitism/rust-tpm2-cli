use std::path::PathBuf;

use clap::Parser;
use log::info;
use tss_esapi::constants::tss::*;
use tss_esapi::tss2_esys::*;

use crate::cli::GlobalOpts;
use crate::handle::ContextSource;
use crate::parse::{self, parse_hex_u32};
use crate::raw_esys::RawEsysContext;

/// Execute the second phase of a two-phase key exchange.
///
/// Wraps TPM2_ZGen_2Phase (raw FFI).
#[derive(Parser)]
pub struct Zgen2PhaseCmd {
    /// Key context file path
    #[arg(
        short = 'c',
        long = "key-context",
        conflicts_with = "key_context_handle"
    )]
    pub key_context: Option<PathBuf>,

    /// Key handle (hex, e.g. 0x81000001)
    #[arg(short = 'H', long = "key-context-handle", value_parser = parse_hex_u32, conflicts_with = "key_context")]
    pub key_context_handle: Option<u32>,

    /// Auth value for the key
    #[arg(short = 'p', long = "auth")]
    pub auth: Option<String>,

    /// Other party's static public point file (raw x||y bytes)
    #[arg(long = "static-public")]
    pub static_public: PathBuf,

    /// Other party's ephemeral public point file (raw x||y bytes)
    #[arg(long = "ephemeral-public")]
    pub ephemeral_public: PathBuf,

    /// Key exchange scheme (ecdh, sm2)
    #[arg(short = 's', long = "scheme", default_value = "ecdh")]
    pub scheme: String,

    /// Counter from the commit
    #[arg(short = 't', long = "counter")]
    pub counter: u16,

    /// Output file for Z1 point
    #[arg(long = "output-Z1")]
    pub output_z1: PathBuf,

    /// Output file for Z2 point
    #[arg(long = "output-Z2")]
    pub output_z2: PathBuf,
}

impl Zgen2PhaseCmd {
    fn key_context_source(&self) -> anyhow::Result<ContextSource> {
        match (&self.key_context, self.key_context_handle) {
            (Some(path), None) => Ok(ContextSource::File(path.clone())),
            (None, Some(handle)) => Ok(ContextSource::Handle(handle)),
            _ => anyhow::bail!(
                "exactly one of --key-context or --key-context-handle must be provided"
            ),
        }
    }

    pub fn execute(&self, global: &GlobalOpts) -> anyhow::Result<()> {
        let mut raw = RawEsysContext::new(global.tcti.as_deref())?;
        let key_handle = raw.resolve_handle_from_source(&self.key_context_source()?)?;

        if let Some(ref auth_str) = self.auth {
            let auth = parse::parse_auth(auth_str)?;
            raw.set_auth(key_handle, auth.value())?;
        }

        let static_data = std::fs::read(&self.static_public)?;
        let ephemeral_data = std::fs::read(&self.ephemeral_public)?;

        let in_qs = bytes_to_ecc_point(&static_data);
        let in_qe = bytes_to_ecc_point(&ephemeral_data);

        let in_scheme: u16 = match self.scheme.to_lowercase().as_str() {
            "ecdh" => TPM2_ALG_ECDH,
            "sm2" => TPM2_ALG_SM2,
            _ => anyhow::bail!("unsupported scheme: {}", self.scheme),
        };

        unsafe {
            let mut z1_ptr: *mut TPM2B_ECC_POINT = std::ptr::null_mut();
            let mut z2_ptr: *mut TPM2B_ECC_POINT = std::ptr::null_mut();

            let rc = Esys_ZGen_2Phase(
                raw.ptr(),
                key_handle,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &in_qs,
                &in_qe,
                in_scheme,
                self.counter,
                &mut z1_ptr,
                &mut z2_ptr,
            );
            if rc != 0 {
                anyhow::bail!("Esys_ZGen_2Phase failed: 0x{rc:08x}");
            }

            if !z1_ptr.is_null() {
                let z1 = ecc_point_to_bytes(&*z1_ptr);
                std::fs::write(&self.output_z1, &z1)?;
                info!("Z1 saved to {}", self.output_z1.display());
                Esys_Free(z1_ptr as *mut _);
            }

            if !z2_ptr.is_null() {
                let z2 = ecc_point_to_bytes(&*z2_ptr);
                std::fs::write(&self.output_z2, &z2)?;
                info!("Z2 saved to {}", self.output_z2.display());
                Esys_Free(z2_ptr as *mut _);
            }
        }

        info!("ZGen_2Phase succeeded");
        Ok(())
    }
}

fn bytes_to_ecc_point(data: &[u8]) -> TPM2B_ECC_POINT {
    let mut point = TPM2B_ECC_POINT::default();
    let half = data.len() / 2;
    let x = &data[..half];
    let y = &data[half..];
    point.point.x.size = x.len() as u16;
    point.point.x.buffer[..x.len()].copy_from_slice(x);
    point.point.y.size = y.len() as u16;
    point.point.y.buffer[..y.len()].copy_from_slice(y);
    point.size = std::mem::size_of::<TPMS_ECC_POINT>() as u16;
    point
}

fn ecc_point_to_bytes(p: &TPM2B_ECC_POINT) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&p.point.x.buffer[..p.point.x.size as usize]);
    out.extend_from_slice(&p.point.y.buffer[..p.point.y.size as usize]);
    out
}
