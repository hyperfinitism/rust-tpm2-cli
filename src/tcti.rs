// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use tss_esapi::tcti_ldr::TctiNameConf;

use crate::error::Tpm2Error;

/// Default TCTI configuration string.
pub(crate) const DEFAULT_TCTI: &str = "device:/dev/tpm0";

/// Default raw device path (used by `send`).
pub(crate) const DEFAULT_DEVICE_PATH: &str = "/dev/tpm0";

/// Parse a TCTI configuration string into a [`TctiNameConf`].
///
/// If `tcti` is `None`, falls back to the `RUST_TPM2_CLI_TCTI` environment
/// variable, then to `device:/dev/tpm0`.
pub fn parse_tcti(tcti: Option<&str>) -> Result<TctiNameConf, Tpm2Error> {
    let tcti_str = match tcti {
        Some(s) => s.to_owned(),
        None => std::env::var("RUST_TPM2_CLI_TCTI").unwrap_or_else(|_| DEFAULT_TCTI.to_owned()),
    };
    TctiNameConf::from_str(&tcti_str).map_err(|e| Tpm2Error::InvalidTcti(e.to_string()))
}

/// Extract the raw device path from a TCTI string.
///
/// Used by `send` to open the TPM device directly.
pub(crate) fn extract_device_path(tcti: Option<&str>) -> String {
    let tcti_str = match tcti {
        Some(s) => s.to_owned(),
        None => std::env::var("RUST_TPM2_CLI_TCTI").unwrap_or_else(|_| DEFAULT_TCTI.to_owned()),
    };
    if let Some(rest) = tcti_str.strip_prefix("device:") {
        rest.to_owned()
    } else {
        DEFAULT_DEVICE_PATH.to_owned()
    }
}
