// SPDX-License-Identifier: Apache-2.0

use tss_esapi::Context;

use crate::error::Tpm2Error;
use crate::tcti::parse_tcti;

/// Create a TPM [`Context`] from an optional TCTI configuration string.
///
/// If `tcti` is `None` the default resolution order applies (env var, then
/// `device:/dev/tpm0`).
pub fn create_context(tcti: Option<&str>) -> Result<Context, Tpm2Error> {
    let tcti_conf = parse_tcti(tcti)?;
    Context::new(tcti_conf).map_err(Tpm2Error::Tss)
}
