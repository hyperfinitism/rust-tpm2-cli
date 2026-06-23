// SPDX-License-Identifier: Apache-2.0

use assert_cmd::Command;

fn assert_parse_error(args: &[&str], expected: &str) {
    let assertion = Command::cargo_bin("tpm2")
        .unwrap()
        .args(args)
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&assertion.get_output().stderr);
    assert!(
        stderr.contains(expected),
        "stderr did not contain {expected:?}: {stderr}"
    );
}

#[test]
fn clockrateadjust_rejects_invalid_rate_before_execution() {
    assert_parse_error(&["clockrateadjust", "warp"], "invalid rate");
}

#[test]
fn pcrextend_rejects_invalid_spec_before_execution() {
    assert_parse_error(&["pcrextend", "32:sha256=00"], "PCR index out of range");
}

#[test]
fn create_rejects_invalid_algorithm_before_execution() {
    assert_parse_error(
        &[
            "create",
            "--parent-context",
            "hex:0x81000000",
            "--key-algorithm",
            "invalid",
        ],
        "unsupported key algorithm",
    );
}

#[test]
fn nvread_rejects_non_nv_handle_before_execution() {
    assert_parse_error(&["nvread", "0x81000000"], "invalid NV index handle");
}

#[test]
fn evictcontrol_rejects_non_persistent_handle_before_execution() {
    assert_parse_error(&["evictcontrol", "0x01000000"], "invalid persistent handle");
}

#[test]
fn create_rejects_unsupported_rsa_key_size_before_execution() {
    assert_parse_error(
        &[
            "create",
            "--parent-context",
            "hex:0x81000000",
            "--key-size",
            "1234",
        ],
        "unsupported RSA key size",
    );
}

#[test]
fn removed_split_symmetric_commands_are_not_accepted() {
    assert_parse_error(&["encrypt"], "unrecognized subcommand");
    assert_parse_error(&["decrypt"], "unrecognized subcommand");
}
