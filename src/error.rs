use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Tpm2Error {
    #[error("TPM error: {0}")]
    Tss(#[from] tss_esapi::Error),

    #[error("invalid TCTI configuration: {0}")]
    InvalidTcti(String),

    #[error("invalid auth value: {0}")]
    InvalidAuth(String),

    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}
