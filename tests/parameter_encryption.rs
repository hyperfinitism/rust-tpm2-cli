// SPDX-License-Identifier: Apache-2.0
//! Parameter encryption tests: encrypted HMAC sessions for getrandom and
//! nvwrite/nvread roundtrips.

mod common;

use common::SwtpmSession;

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
