// SPDX-License-Identifier: Apache-2.0

use tss_esapi::Context;

use crate::error::Tpm2Error;
use crate::tcti::{TctiConfig, default_tcti};

/// Create a TPM [`Context`] from a configuration parsed by clap.
pub fn create_context(tcti: Option<&TctiConfig>) -> Result<Context, Tpm2Error> {
    let tcti_conf = tcti.cloned().unwrap_or_else(default_tcti).name_conf();
    Context::new(tcti_conf).map_err(Tpm2Error::Tss)
}
