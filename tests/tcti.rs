// SPDX-License-Identifier: Apache-2.0
//! TCTI configuration tests.
//!
//! Tests the `-T` flag and `RUST_TPM2_CLI_TCTI` env var for connecting
//! to the TPM. Validates valid endpoints, invalid endpoints, invalid
//! prefixes, and precedence rules.

mod common;

use assert_cmd::Command;
use common::SwtpmSession;

#[test]
fn valid_swtpm_uds_endpoint_via_t_flag() {
    let s = SwtpmSession::new_uds();
    s.cmd("getrandom").args(["1", "--hex"]).assert().success();
}

#[test]
fn valid_swtpm_tcp_endpoint_via_t_flag() {
    let s = SwtpmSession::new_tcp();
    s.cmd("getrandom").args(["1", "--hex"]).assert().success();
}

#[test]
fn swtpm_uds_env_var_works() {
    let s = SwtpmSession::new_uds();
    let mut cmd = Command::cargo_bin("tpm2").unwrap();
    cmd.args(["-v", "Off", "getrandom", "1", "--hex"]);
    cmd.env("RUST_TPM2_CLI_TCTI", s.tcti());
    cmd.assert().success();
}

#[test]
fn swtpm_tcp_env_var_works() {
    let s = SwtpmSession::new_tcp();
    let mut cmd = Command::cargo_bin("tpm2").unwrap();
    cmd.args(["-v", "Off", "getrandom", "1", "--hex"]);
    cmd.env("RUST_TPM2_CLI_TCTI", s.tcti());
    cmd.assert().success();
}

#[test]
fn invalid_port_fails() {
    let mut cmd = Command::cargo_bin("tpm2").unwrap();
    cmd.args([
        "-v",
        "Off",
        "-T",
        "swtpm:host=localhost,port=0",
        "startup",
        "--clear",
    ]);
    cmd.assert().failure();
}

#[test]
fn invalid_tcti_prefix_fails() {
    let mut cmd = Command::cargo_bin("tpm2").unwrap();
    cmd.args(["-v", "Off", "-T", "bogus:foo=bar", "startup", "--clear"]);
    cmd.assert().failure();
}

#[test]
fn t_flag_takes_precedence_over_env_var() {
    let s = SwtpmSession::new();
    let mut cmd = Command::cargo_bin("tpm2").unwrap();
    cmd.args(["-v", "Off", "-T", &s.tcti(), "getrandom", "1", "--hex"]);
    cmd.env("RUST_TPM2_CLI_TCTI", "swtpm:host=localhost,port=0");
    cmd.assert().success();
}

#[test]
fn env_var_invalid_endpoint_fails() {
    let mut cmd = Command::cargo_bin("tpm2").unwrap();
    cmd.args(["-v", "Off", "startup", "--clear"]);
    cmd.env("RUST_TPM2_CLI_TCTI", "swtpm:host=localhost,port=0");
    cmd.assert().failure();
}
