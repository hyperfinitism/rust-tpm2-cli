use clap::Parser;

use crate::cli::GlobalOpts;

/// Decode a TPM2 response code into human-readable text.
///
/// This is a client-side utility that does not contact the TPM.
#[derive(Parser)]
pub struct RcDecodeCmd {
    /// Response code (hex, e.g. 0x100)
    #[arg()]
    pub rc: String,
}

impl RcDecodeCmd {
    pub fn execute(&self, _global: &GlobalOpts) -> anyhow::Result<()> {
        let stripped = self
            .rc
            .strip_prefix("0x")
            .or_else(|| self.rc.strip_prefix("0X"))
            .unwrap_or(&self.rc);
        let code: u32 = u32::from_str_radix(stripped, 16)
            .map_err(|_| anyhow::anyhow!("invalid response code: {}", self.rc))?;

        println!("0x{code:08X}:");

        // Decode the error format
        let fmt1 = (code & 0x80) != 0;

        if code == 0 {
            println!("  TPM_RC_SUCCESS");
            return Ok(());
        }

        // Check for format 1 (parameter/session/handle errors)
        if fmt1 {
            let error_number = code & 0x3F;
            let parameter = (code >> 8) & 0xF;
            let session_handle = (code >> 8) & 0x7;
            let is_parameter = (code & 0x40) != 0;

            let error_name = decode_fmt1_error(error_number);

            if is_parameter {
                println!("  format 1 error");
                println!("  error: {error_name} (0x{error_number:03x})");
                println!("  parameter: {parameter}");
            } else {
                println!("  format 1 error");
                println!("  error: {error_name} (0x{error_number:03x})");
                println!("  session/handle: {session_handle}");
            }
        } else {
            let error_number = code & 0x7F;
            let error_name = decode_fmt0_error(error_number);
            println!("  format 0 error");
            println!("  error: {error_name} (0x{error_number:03x})");
        }

        Ok(())
    }
}

fn decode_fmt1_error(n: u32) -> &'static str {
    match n {
        0x01 => "TPM_RC_ASYMMETRIC",
        0x02 => "TPM_RC_ATTRIBUTES",
        0x03 => "TPM_RC_HASH",
        0x04 => "TPM_RC_VALUE",
        0x05 => "TPM_RC_HIERARCHY",
        0x07 => "TPM_RC_KEY_SIZE",
        0x08 => "TPM_RC_MGF",
        0x09 => "TPM_RC_MODE",
        0x0A => "TPM_RC_TYPE",
        0x0B => "TPM_RC_HANDLE",
        0x0C => "TPM_RC_KDF",
        0x0D => "TPM_RC_RANGE",
        0x0E => "TPM_RC_AUTH_FAIL",
        0x0F => "TPM_RC_NONCE",
        0x10 => "TPM_RC_PP",
        0x12 => "TPM_RC_SCHEME",
        0x15 => "TPM_RC_SIZE",
        0x16 => "TPM_RC_SYMMETRIC",
        0x17 => "TPM_RC_TAG",
        0x18 => "TPM_RC_SELECTOR",
        0x1A => "TPM_RC_INSUFFICIENT",
        0x1B => "TPM_RC_SIGNATURE",
        0x1C => "TPM_RC_KEY",
        0x1D => "TPM_RC_POLICY_FAIL",
        0x1F => "TPM_RC_INTEGRITY",
        0x20 => "TPM_RC_TICKET",
        0x21 => "TPM_RC_RESERVED_BITS",
        0x22 => "TPM_RC_BAD_AUTH",
        0x23 => "TPM_RC_EXPIRED",
        0x24 => "TPM_RC_POLICY_CC",
        0x25 => "TPM_RC_BINDING",
        0x26 => "TPM_RC_CURVE",
        0x27 => "TPM_RC_ECC_POINT",
        _ => "UNKNOWN",
    }
}

fn decode_fmt0_error(n: u32) -> &'static str {
    match n {
        0x00 => "TPM_RC_SUCCESS",
        0x01 => "TPM_RC_INITIALIZE",
        0x03 => "TPM_RC_FAILURE",
        0x0B => "TPM_RC_SEQUENCE",
        0x19 => "TPM_RC_PRIVATE",
        0x20 => "TPM_RC_HMAC",
        0x23 => "TPM_RC_DISABLED",
        0x24 => "TPM_RC_EXCLUSIVE",
        0x25 => "TPM_RC_AUTH_TYPE",
        0x26 => "TPM_RC_AUTH_MISSING",
        0x27 => "TPM_RC_POLICY",
        0x28 => "TPM_RC_PCR",
        0x29 => "TPM_RC_PCR_CHANGED",
        0x2D => "TPM_RC_UPGRADE",
        0x2E => "TPM_RC_TOO_MANY_CONTEXTS",
        0x2F => "TPM_RC_AUTH_UNAVAILABLE",
        0x30 => "TPM_RC_REBOOT",
        0x31 => "TPM_RC_UNBALANCED",
        0x42 => "TPM_RC_COMMAND_SIZE",
        0x43 => "TPM_RC_COMMAND_CODE",
        0x44 => "TPM_RC_AUTHSIZE",
        0x45 => "TPM_RC_AUTH_CONTEXT",
        0x46 => "TPM_RC_NV_RANGE",
        0x47 => "TPM_RC_NV_SIZE",
        0x48 => "TPM_RC_NV_LOCKED",
        0x49 => "TPM_RC_NV_AUTHORIZATION",
        0x4A => "TPM_RC_NV_UNINITIALIZED",
        0x4B => "TPM_RC_NV_SPACE",
        0x4C => "TPM_RC_NV_DEFINED",
        0x50 => "TPM_RC_BAD_CONTEXT",
        0x51 => "TPM_RC_CPHASH",
        0x52 => "TPM_RC_PARENT",
        0x53 => "TPM_RC_NEEDS_TEST",
        0x54 => "TPM_RC_NO_RESULT",
        0x55 => "TPM_RC_SENSITIVE",
        _ => "UNKNOWN",
    }
}
