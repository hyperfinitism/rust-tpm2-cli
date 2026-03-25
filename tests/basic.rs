// SPDX-License-Identifier: Apache-2.0
//! Basic TPM operations: startup, shutdown, getrandom, selftest,
//! gettestresult, incrementalselftest, testparms, stirrandom,
//! readclock, getcap, rcdecode, print.

mod common;

use common::SwtpmSession;

// ── startup / shutdown ──────────────────────────────────────────────

#[test]
fn startup_clear() {
    let s = SwtpmSession::new(); // already does startup --clear
    s.cmd("shutdown").arg("--clear").assert().success();
    s.cmd("startup").arg("--clear").assert().success();
}

#[test]
fn startup_state() {
    let s = SwtpmSession::new();
    s.cmd("shutdown").assert().success();
    s.cmd("startup").assert().success();
}

// ── getrandom ───────────────────────────────────────────────────────

#[test]
fn getrandom_hex_16_bytes() {
    let s = SwtpmSession::new();
    let output = s.cmd("getrandom").args(["16", "--hex"]).output().unwrap();
    assert!(output.status.success());
    let hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(hex.len(), 32, "16 bytes should produce 32 hex chars");
}

#[test]
fn getrandom_to_file() {
    let s = SwtpmSession::new();
    let out_file = s.tmp().path().join("rand.bin");
    s.cmd("getrandom")
        .args(["32", "-o"])
        .arg(&out_file)
        .assert()
        .success();
    let data = std::fs::read(&out_file).unwrap();
    assert_eq!(data.len(), 32);
}

#[test]
fn getrandom_1_byte() {
    let s = SwtpmSession::new();
    let output = s.cmd("getrandom").args(["1", "--hex"]).output().unwrap();
    assert!(output.status.success());
    let hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(hex.len(), 2);
}

// ── selftest ────────────────────────────────────────────────────────

#[test]
fn selftest_full() {
    let s = SwtpmSession::new();
    s.cmd("selftest").arg("--full-test").assert().success();
}

#[test]
fn gettestresult() {
    let s = SwtpmSession::new();
    s.cmd("gettestresult").assert().success();
}

#[test]
fn incrementalselftest_sha256() {
    let s = SwtpmSession::new();
    s.cmd("incrementalselftest")
        .arg("sha256")
        .assert()
        .success();
}

// ── testparms ───────────────────────────────────────────────────────

#[test]
fn testparms_rsa2048() {
    let s = SwtpmSession::new();
    s.cmd("testparms").arg("rsa2048").assert().success();
}

#[test]
fn testparms_aes128() {
    let s = SwtpmSession::new();
    s.cmd("testparms").arg("aes128").assert().success();
}

#[test]
fn testparms_keyedhash() {
    let s = SwtpmSession::new();
    s.cmd("testparms").arg("keyedhash").assert().success();
}

// ── stirrandom ──────────────────────────────────────────────────────

#[test]
fn stirrandom() {
    let s = SwtpmSession::new();
    let entropy_file = s.write_tmp_file("entropy.bin", &[0xAB; 32]);
    s.cmd("stirrandom")
        .arg("-i")
        .arg(&entropy_file)
        .assert()
        .success();
}

// ── readclock ───────────────────────────────────────────────────────

#[test]
fn readclock() {
    let s = SwtpmSession::new();
    s.cmd("readclock").assert().success();
}

// ── getcap ──────────────────────────────────────────────────────────

#[test]
fn getcap_list() {
    let s = SwtpmSession::new();
    s.cmd("getcap").arg("--list").assert().success();
}

#[test]
fn getcap_algorithms() {
    let s = SwtpmSession::new();
    s.cmd("getcap").arg("algorithms").assert().success();
}

#[test]
fn getcap_pcrs() {
    let s = SwtpmSession::new();
    s.cmd("getcap").arg("pcrs").assert().success();
}

#[test]
fn getcap_properties_fixed() {
    let s = SwtpmSession::new();
    s.cmd("getcap").arg("properties-fixed").assert().success();
}

#[test]
fn getcap_properties_variable() {
    let s = SwtpmSession::new();
    s.cmd("getcap")
        .arg("properties-variable")
        .assert()
        .success();
}

#[test]
fn getcap_ecc_curves() {
    let s = SwtpmSession::new();
    s.cmd("getcap").arg("ecc-curves").assert().success();
}

#[test]
fn getcap_handles_persistent() {
    let s = SwtpmSession::new();
    s.cmd("getcap").arg("handles-persistent").assert().success();
}

// ── rcdecode ────────────────────────────────────────────────────────

#[test]
fn rcdecode_success() {
    let s = SwtpmSession::new();
    s.cmd("rcdecode").arg("0x000").assert().success();
}

#[test]
fn rcdecode_initialize() {
    let s = SwtpmSession::new();
    s.cmd("rcdecode").arg("0x100").assert().success();
}

// ── print ───────────────────────────────────────────────────────────

#[test]
fn print_tpmt_public() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let pub_file = s.tmp().path().join("pub.bin");
    s.cmd("readpublic")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .arg("-o")
        .arg(&pub_file)
        .assert()
        .success();
    s.cmd("print")
        .args(["-t", "TPMT_PUBLIC"])
        .arg(&pub_file)
        .assert()
        .success();
}

#[test]
fn print_tpms_context() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    s.cmd("print")
        .args(["-t", "TPMS_CONTEXT"])
        .arg(&primary_ctx)
        .assert()
        .success();
}
