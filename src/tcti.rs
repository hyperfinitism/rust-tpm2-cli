// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use tss_esapi::tcti_ldr::TctiNameConf;

use crate::error::Tpm2Error;

/// Default TCTI configuration string.
pub(crate) const DEFAULT_TCTI: &str = "device:/dev/tpm0";

/// Default raw device path (used by `send`).
pub(crate) const DEFAULT_DEVICE_PATH: &str = "/dev/tpm0";

/// A TCTI configuration parsed at the CLI boundary.
#[derive(Debug, Clone)]
pub struct TctiConfig {
    raw: String,
    name_conf: TctiNameConf,
}

impl TctiConfig {
    pub fn name_conf(&self) -> TctiNameConf {
        self.name_conf.clone()
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl FromStr for TctiConfig {
    type Err = Tpm2Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.contains('\0') {
            return Err(Tpm2Error::InvalidTcti(
                "TCTI configuration contains an embedded NUL".to_owned(),
            ));
        }
        let name_conf =
            TctiNameConf::from_str(value).map_err(|e| Tpm2Error::InvalidTcti(e.to_string()))?;
        Ok(Self {
            raw: value.to_owned(),
            name_conf,
        })
    }
}

pub(crate) fn default_tcti() -> TctiConfig {
    DEFAULT_TCTI
        .parse()
        .expect("the built-in default TCTI configuration must be valid")
}

/// Extract the raw device path from a parsed TCTI configuration.
pub(crate) fn extract_device_path(tcti: Option<&TctiConfig>) -> String {
    tcti.and_then(|config| config.as_str().strip_prefix("device:"))
        .unwrap_or(DEFAULT_DEVICE_PATH)
        .to_owned()
}
