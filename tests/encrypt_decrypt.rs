// SPDX-License-Identifier: Apache-2.0
//! Encrypt/decrypt tests: rsaencrypt, rsadecrypt, encrypt, decrypt.

mod common;

use common::SwtpmSession;

#[test]
fn rsaencrypt_on_primary_key() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let plain = s.write_tmp_file("plain.bin", b"plaintext data!!");
    let cipher = s.tmp().path().join("cipher.bin");
    s.cmd("rsaencrypt")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-i")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();
    assert!(std::fs::metadata(&cipher).unwrap().len() > 0);
}

#[test]
fn rsadecrypt_on_restricted_key_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    let plain = s.write_tmp_file("plain.bin", b"plaintext data!!");
    let cipher = s.tmp().path().join("cipher.bin");
    s.cmd("rsaencrypt")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-i")
        .arg(&plain)
        .arg("-o")
        .arg(&cipher)
        .assert()
        .success();

    s.cmd("rsadecrypt")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-i")
        .arg(&cipher)
        .arg("-o")
        .arg(s.tmp().path().join("dec.bin"))
        .assert()
        .failure();
}

#[test]
fn encrypt_without_valid_symmetric_key_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    s.cmd("encrypt")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-o")
        .arg(s.tmp().path().join("enc_out.bin"))
        .write_stdin("test")
        .assert()
        .failure();
}

#[test]
fn decrypt_without_valid_symmetric_key_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");
    s.cmd("decrypt")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-o")
        .arg(s.tmp().path().join("dec_out.bin"))
        .write_stdin("test")
        .assert()
        .failure();
}
