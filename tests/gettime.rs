// SPDX-License-Identifier: Apache-2.0
//! Gettime tests: gettime + verifysignature integration.

mod common;

use common::SwtpmSession;

#[test]
fn gettime_produces_attestation_and_signature() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("primary");
    let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");
    let nonce = s.tmp().path().join("nonce.bin");
    s.cmd("getrandom")
        .args(["32", "-o"])
        .arg(&nonce)
        .assert()
        .success();

    let attest = s.tmp().path().join("time_attest.bin");
    let sig = s.tmp().path().join("time_sig.bin");
    s.cmd("gettime")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&key_ctx))
        .args(["-g", "sha256", "-q"])
        .arg(format!("file:{}", nonce.display()))
        .arg("-o")
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
    assert!(std::fs::metadata(&attest).unwrap().len() > 0);
    assert!(std::fs::metadata(&sig).unwrap().len() > 0);
}

#[test]
fn verifysignature_on_gettime_attestation() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("primary");
    let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");
    let nonce = s.tmp().path().join("nonce.bin");
    s.cmd("getrandom")
        .args(["32", "-o"])
        .arg(&nonce)
        .assert()
        .success();

    let attest = s.tmp().path().join("time_attest.bin");
    let sig = s.tmp().path().join("time_sig.bin");
    s.cmd("gettime")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&key_ctx))
        .args(["-g", "sha256", "-q"])
        .arg(format!("file:{}", nonce.display()))
        .arg("-o")
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    s.cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&key_ctx))
        .args(["-g", "sha256", "-m"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

#[test]
fn gettime_without_nonce() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("primary");
    let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");

    let attest = s.tmp().path().join("time_attest.bin");
    let sig = s.tmp().path().join("time_sig.bin");
    s.cmd("gettime")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&key_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
    assert!(std::fs::metadata(&attest).unwrap().len() > 0);
}

#[test]
fn verifysignature_gettime_wrong_key_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("primary");
    let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");
    let (wrong_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "wrong_key");

    let attest = s.tmp().path().join("time_attest.bin");
    let sig = s.tmp().path().join("time_sig.bin");
    s.cmd("gettime")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&key_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    s.cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&wrong_ctx))
        .args(["-g", "sha256", "-m"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .failure();
}

#[test]
fn verifysignature_gettime_corrupted_attestation_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("primary");
    let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");

    let attest = s.tmp().path().join("time_attest.bin");
    let sig = s.tmp().path().join("time_sig.bin");
    s.cmd("gettime")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&key_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    let bad_attest = s.corrupt_file(&attest, "time_attest_bad.bin", 10);

    s.cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&key_ctx))
        .args(["-g", "sha256", "-m"])
        .arg(&bad_attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .failure();
}
