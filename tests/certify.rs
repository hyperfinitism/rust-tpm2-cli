// SPDX-License-Identifier: Apache-2.0
//! Certify tests: certify + verifysignature integration.

mod common;

use common::SwtpmSession;

#[test]
fn certify_object() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
    let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");

    let attest = s.tmp().path().join("certify_attest.bin");
    let sig = s.tmp().path().join("certify_sig.bin");
    s.cmd("certify")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&target_ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&certifier_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
    assert!(std::fs::metadata(&attest).unwrap().len() > 0);
    assert!(std::fs::metadata(&sig).unwrap().len() > 0);
}

#[test]
fn verifysignature_on_certify_attestation() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
    let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");

    let attest = s.tmp().path().join("certify_attest.bin");
    let sig = s.tmp().path().join("certify_sig.bin");
    s.cmd("certify")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&target_ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&certifier_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    s.cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&certifier_ctx))
        .args(["-g", "sha256", "-m"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

#[test]
fn certify_with_qualification() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
    let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");

    let attest = s.tmp().path().join("certify_q_attest.bin");
    let sig = s.tmp().path().join("certify_q_sig.bin");
    s.cmd("certify")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&target_ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&certifier_ctx))
        .args(["-g", "sha256", "-q", "hex:cafebabe", "-o"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
    assert!(std::fs::metadata(&attest).unwrap().len() > 0);
}

#[test]
fn verifysignature_certify_wrong_key_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
    let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");
    let (wrong_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "wrong_cert");

    let attest = s.tmp().path().join("certify_attest.bin");
    let sig = s.tmp().path().join("certify_sig.bin");
    s.cmd("certify")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&target_ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&certifier_ctx))
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
fn verifysignature_certify_corrupted_data_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
    let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");

    let attest = s.tmp().path().join("certify_attest.bin");
    let sig = s.tmp().path().join("certify_sig.bin");
    s.cmd("certify")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&target_ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&certifier_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    let bad_attest = s.corrupt_file(&attest, "certify_attest_bad.bin", 10);

    s.cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&certifier_ctx))
        .args(["-g", "sha256", "-m"])
        .arg(&bad_attest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .failure();
}
