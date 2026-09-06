// SPDX-License-Identifier: Apache-2.0

//! Integration tests for utility commands and CLI infrastructure that do not
//! correspond one-to-one with TPM 2.0 commands.

mod common;

#[path = "utilities/ak_ek.rs"]
mod ak_ek;
#[path = "utilities/output.rs"]
mod output;
#[path = "utilities/policy.rs"]
mod policy;
#[path = "utilities/session.rs"]
mod session;
#[path = "utilities/tcti.rs"]
mod tcti;
