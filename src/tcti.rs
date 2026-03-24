// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use tss_esapi::tcti_ldr::TctiNameConf;

use crate::error::Tpm2Error;

/// Default TCTI configuration string.
pub(crate) const DEFAULT_TCTI: &str = "device:/dev/tpm0";

/// Default raw device path (used by `send`).
pub(crate) const DEFAULT_DEVICE_PATH: &str = "/dev/tpm0";

/// Resolve the TCTI configuration string.
///
/// Resolution order:
/// 1. Explicit `tcti` argument
/// 2. `RUST_TPM2_CLI_TCTI` environment variable
/// 3. `device:/dev/tpm0` (default)
///
/// tss-esapi 8.x supports:
/// - `device:/dev/tpmrm0`
/// - `mssim:host=localhost,port=2321`
/// - `swtpm:host=localhost,port=2321`  (TCP)
/// - `swtpm:path=/tmp/swtpm-sock`      (Unix socket)
/// - `libtpms:`
/// - `tabrmd:`
pub(crate) fn resolve_tcti_str(tcti: Option<&str>) -> String {
    if let Some(s) = tcti {
        return s.to_owned();
    }
    if let Ok(val) = std::env::var("RUST_TPM2_CLI_TCTI")
        && !val.is_empty()
    {
        return val;
    }
    DEFAULT_TCTI.to_owned()
}

/// Parse a TCTI configuration string into a [`TctiNameConf`].
pub fn parse_tcti(tcti: Option<&str>) -> Result<TctiNameConf, Tpm2Error> {
    let tcti_str = resolve_tcti_str(tcti);
    TctiNameConf::from_str(&tcti_str).map_err(|e| Tpm2Error::InvalidTcti(e.to_string()))
}

/// Extract the raw device path from a TCTI string.
///
/// Used by `send` to open the TPM device directly.
pub(crate) fn extract_device_path(tcti: Option<&str>) -> String {
    let tcti_str = resolve_tcti_str(tcti);
    if let Some(rest) = tcti_str.strip_prefix("device:") {
        rest.to_owned()
    } else {
        DEFAULT_DEVICE_PATH.to_owned()
    }
}
