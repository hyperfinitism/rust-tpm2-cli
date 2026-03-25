// SPDX-License-Identifier: Apache-2.0
//! HMAC computation tests using TPM-loaded HMAC keys.

mod common;

use common::SwtpmSession;

#[test]
fn hmac_compute_and_verify_size() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    // Create an HMAC key under the primary.
    let priv_f = s.tmp().path().join("hmac.priv");
    let pub_f = s.tmp().path().join("hmac.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .args(["-G", "hmac", "-g", "sha256", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();

    let ctx = s.tmp().path().join("hmac.ctx");
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-r")
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .arg("-c")
        .arg(&ctx)
        .assert()
        .success();

    let input = s.write_tmp_file("input.bin", b"hello world");
    let output = s.tmp().path().join("hmac_out.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx))
        .args(["-g", "sha256", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&output)
        .assert()
        .success();

    let hmac_val = std::fs::read(&output).unwrap();
    assert_eq!(hmac_val.len(), 32, "SHA-256 HMAC should be 32 bytes");
}

#[test]
fn hmac_is_deterministic() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let priv_f = s.tmp().path().join("hmac.priv");
    let pub_f = s.tmp().path().join("hmac.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .args(["-G", "hmac", "-g", "sha256", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();

    let ctx = s.tmp().path().join("hmac.ctx");
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-r")
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .arg("-c")
        .arg(&ctx)
        .assert()
        .success();

    let input = s.write_tmp_file("input.bin", b"deterministic hmac");

    let out1 = s.tmp().path().join("hmac1.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx))
        .args(["-g", "sha256", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&out1)
        .assert()
        .success();

    let out2 = s.tmp().path().join("hmac2.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx))
        .args(["-g", "sha256", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&out2)
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "same key + same data must produce same HMAC"
    );
}

#[test]
fn hmac_different_data_different_result() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let priv_f = s.tmp().path().join("hmac.priv");
    let pub_f = s.tmp().path().join("hmac.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .args(["-G", "hmac", "-g", "sha256", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();

    let ctx = s.tmp().path().join("hmac.ctx");
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-r")
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .arg("-c")
        .arg(&ctx)
        .assert()
        .success();

    let input_a = s.write_tmp_file("a.bin", b"data_a");
    let input_b = s.write_tmp_file("b.bin", b"data_b");

    let out_a = s.tmp().path().join("hmac_a.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx))
        .args(["-g", "sha256", "-i"])
        .arg(&input_a)
        .arg("-o")
        .arg(&out_a)
        .assert()
        .success();

    let out_b = s.tmp().path().join("hmac_b.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx))
        .args(["-g", "sha256", "-i"])
        .arg(&input_b)
        .arg("-o")
        .arg(&out_b)
        .assert()
        .success();

    assert_ne!(
        std::fs::read(&out_a).unwrap(),
        std::fs::read(&out_b).unwrap(),
    );
}

#[test]
fn hmac_different_keys_different_result() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");

    // Key 1
    let priv1 = s.tmp().path().join("hmac1.priv");
    let pub1 = s.tmp().path().join("hmac1.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .args(["-G", "hmac", "-g", "sha256", "-r"])
        .arg(&priv1)
        .arg("-u")
        .arg(&pub1)
        .assert()
        .success();
    let ctx1 = s.tmp().path().join("hmac1.ctx");
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-r")
        .arg(&priv1)
        .arg("-u")
        .arg(&pub1)
        .arg("-c")
        .arg(&ctx1)
        .assert()
        .success();

    // Key 2
    let priv2 = s.tmp().path().join("hmac2.priv");
    let pub2 = s.tmp().path().join("hmac2.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .args(["-G", "hmac", "-g", "sha256", "-r"])
        .arg(&priv2)
        .arg("-u")
        .arg(&pub2)
        .assert()
        .success();
    let ctx2 = s.tmp().path().join("hmac2.ctx");
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-r")
        .arg(&priv2)
        .arg("-u")
        .arg(&pub2)
        .arg("-c")
        .arg(&ctx2)
        .assert()
        .success();

    let input = s.write_tmp_file("input.bin", b"same data for both keys");

    let out1 = s.tmp().path().join("out1.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx1))
        .args(["-g", "sha256", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&out1)
        .assert()
        .success();

    let out2 = s.tmp().path().join("out2.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx2))
        .args(["-g", "sha256", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&out2)
        .assert()
        .success();

    assert_ne!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "different keys must produce different HMACs for same data"
    );
}
