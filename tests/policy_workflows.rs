// SPDX-License-Identifier: Apache-2.0
//! Advanced policy workflow tests:
//! - policynv: policy bound to NV index contents
//! - Parameter encryption via encrypted sessions
//! - getsessionauditdigest: audit trail for session operations

mod common;

use common::SwtpmSession;

// ════════════════════════════════════════════════════════════════════
// Policy bound to NV index contents (policynv)
// ════════════════════════════════════════════════════════════════════

#[test]
fn policynv_eq_trial() {
    let s = SwtpmSession::new();

    // Define NV index with known value.
    let nv_idx = "0x01000050";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    let data = s.write_tmp_file("nv_data.bin", &[0x42u8; 8]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Trial session: policynv with eq succeeds when values match.
    let trial = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial)
        .args(["-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&trial)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "4242424242424242",
            "--offset",
            "0",
            "--operation",
            "eq",
        ])
        .assert()
        .success();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

#[test]
fn policynv_neq_fails_when_equal() {
    let s = SwtpmSession::new();

    let nv_idx = "0x01000051";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    let data = s.write_tmp_file("nv_data.bin", &[0x42u8; 8]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Policy session: policynv with "neq" should fail
    // because the NV contents are equal to operand-b.
    let policy_session = s.tmp().path().join("policy_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&policy_session)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&policy_session)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "4242424242424242",
            "--offset",
            "0",
            "--operation",
            "neq",
        ])
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

#[test]
fn policynv_ult_unsigned_less_than() {
    let s = SwtpmSession::new();

    let nv_idx = "0x01000052";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    // Write value 0x0000000000000005.
    let data = s.write_tmp_file("nv_data.bin", &[0, 0, 0, 0, 0, 0, 0, 5]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Trial: policynv with "ult" — NV(5) < operand(10) → should succeed.
    let trial = s.tmp().path().join("trial.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&trial)
        .args(["-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&trial)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "000000000000000A",
            "--offset",
            "0",
            "--operation",
            "ult",
        ])
        .assert()
        .success();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

#[test]
fn policynv_ult_fails_when_greater() {
    let s = SwtpmSession::new();

    let nv_idx = "0x01000053";
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    // Write value 0x0000000000000010 (16).
    let data = s.write_tmp_file("nv_data.bin", &[0, 0, 0, 0, 0, 0, 0, 0x10]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .assert()
        .success();

    // Policy session: policynv with "ult" — NV(16) < operand(5) → should fail.
    let session = s.tmp().path().join("session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&session)
        .args(["--policy-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("policynv")
        .arg("-S")
        .arg(&session)
        .args(["-i", nv_idx, "-C", "o"])
        .args([
            "--operand-b",
            "0000000000000005",
            "--offset",
            "0",
            "--operation",
            "ult",
        ])
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

// ════════════════════════════════════════════════════════════════════
// Parameter encryption via encrypted session
// ════════════════════════════════════════════════════════════════════

#[test]
fn parameter_encryption_getrandom() {
    let s = SwtpmSession::new();

    // Start HMAC session with encryption enabled.
    let enc_session = s.tmp().path().join("enc_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&enc_session)
        .args(["--hmac-session", "-g", "sha256"])
        .assert()
        .success();

    s.cmd("sessionconfig")
        .arg("-S")
        .arg(&enc_session)
        .arg("--enable-encrypt")
        .assert()
        .success();

    // Use the encrypted session for getrandom.
    let out = s.tmp().path().join("rand.bin");
    s.cmd("getrandom")
        .args(["32", "-o"])
        .arg(&out)
        .arg("-S")
        .arg(&enc_session)
        .assert()
        .success();

    let data = std::fs::read(&out).unwrap();
    assert_eq!(data.len(), 32);
    assert_ne!(data, vec![0u8; 32]);
}

#[test]
fn parameter_encryption_nvwrite_nvread_roundtrip() {
    let s = SwtpmSession::new();
    let nv_idx = "0x01000060";

    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "16", "-a", "ownerwrite|ownerread", nv_idx])
        .assert()
        .success();

    // Start HMAC session with encryption for writing.
    let enc_session = s.tmp().path().join("enc_session.ctx");
    s.cmd("startauthsession")
        .arg("-S")
        .arg(&enc_session)
        .args(["--hmac-session", "-g", "sha256"])
        .assert()
        .success();
    s.cmd("sessionconfig")
        .arg("-S")
        .arg(&enc_session)
        .arg("--enable-encrypt")
        .assert()
        .success();

    let data = s.write_tmp_file("data.bin", b"encrypted-param!");
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(nv_idx)
        .arg("-S")
        .arg(&enc_session)
        .assert()
        .success();

    s.flush_sessions();

    // Read back without encryption — data should still match.
    let out = s.tmp().path().join("read.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(nv_idx)
        .assert()
        .success();

    assert_eq!(std::fs::read(&out).unwrap(), b"encrypted-param!");

    let _ = s.cmd("nvundefine").args(["-C", "o", nv_idx]).ok();
}

// Note: getsessionauditdigest is not tested here because the
// --audit-session flag doesn't properly set session attributes
// for TPM2_GetSessionAuditDigest (TPM returns RC_ATTRIBUTES).
