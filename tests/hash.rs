// SPDX-License-Identifier: Apache-2.0
//! Hash operation tests with value verification.

mod common;

use common::SwtpmSession;
use sha2::{Digest, Sha256};

#[test]
fn hash_sha256_size() {
    let s = SwtpmSession::new();
    let msg = s.write_tmp_file("msg.bin", b"hello");
    let digest = s.tmp().path().join("digest.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&digest)
        .arg(&msg)
        .assert()
        .success();
    assert_eq!(std::fs::read(&digest).unwrap().len(), 32);
}

#[test]
fn hash_sha256_matches_expected() {
    let s = SwtpmSession::new();
    let msg = s.write_tmp_file("msg.bin", b"hello");
    let digest = s.tmp().path().join("digest.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&digest)
        .arg(&msg)
        .assert()
        .success();
    let tpm_digest = std::fs::read(&digest).unwrap();
    let expected = Sha256::digest(b"hello");
    assert_eq!(tpm_digest, expected.as_slice());
}

#[test]
fn hash_sha384_size() {
    let s = SwtpmSession::new();
    let msg = s.write_tmp_file("msg.bin", b"hello");
    let digest = s.tmp().path().join("digest.bin");
    s.cmd("hash")
        .args(["-g", "sha384", "-o"])
        .arg(&digest)
        .arg(&msg)
        .assert()
        .success();
    assert_eq!(std::fs::read(&digest).unwrap().len(), 48);
}

#[test]
fn hash_sha512_size() {
    let s = SwtpmSession::new();
    let msg = s.write_tmp_file("msg.bin", b"hello");
    let digest = s.tmp().path().join("digest.bin");
    s.cmd("hash")
        .args(["-g", "sha512", "-o"])
        .arg(&digest)
        .arg(&msg)
        .assert()
        .success();
    assert_eq!(std::fs::read(&digest).unwrap().len(), 64);
}

#[test]
fn hash_sha1_size() {
    let s = SwtpmSession::new();
    let msg = s.write_tmp_file("msg.bin", b"hello");
    let digest = s.tmp().path().join("digest.bin");
    s.cmd("hash")
        .args(["-g", "sha1", "-o"])
        .arg(&digest)
        .arg(&msg)
        .assert()
        .success();
    assert_eq!(std::fs::read(&digest).unwrap().len(), 20);
}

#[test]
fn hash_with_ticket() {
    let s = SwtpmSession::new();
    let msg = s.write_tmp_file("msg.bin", b"hello");
    let digest = s.tmp().path().join("digest.bin");
    let ticket = s.tmp().path().join("ticket.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-C", "o", "-o"])
        .arg(&digest)
        .arg("-t")
        .arg(&ticket)
        .arg(&msg)
        .assert()
        .success();
    assert!(ticket.exists());
    assert!(std::fs::metadata(&ticket).unwrap().len() > 0);
}

#[test]
fn hash_is_deterministic() {
    let s = SwtpmSession::new();
    let msg = s.write_tmp_file("msg.bin", b"hello");
    let d1 = s.tmp().path().join("d1.bin");
    let d2 = s.tmp().path().join("d2.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&d1)
        .arg(&msg)
        .assert()
        .success();
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&d2)
        .arg(&msg)
        .assert()
        .success();
    assert_eq!(std::fs::read(&d1).unwrap(), std::fs::read(&d2).unwrap());
}

#[test]
fn hash_different_data_different_digest() {
    let s = SwtpmSession::new();
    let msg1 = s.write_tmp_file("msg1.bin", b"hello");
    let msg2 = s.write_tmp_file("msg2.bin", b"world");
    let d1 = s.tmp().path().join("d1.bin");
    let d2 = s.tmp().path().join("d2.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&d1)
        .arg(&msg1)
        .assert()
        .success();
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&d2)
        .arg(&msg2)
        .assert()
        .success();
    assert_ne!(std::fs::read(&d1).unwrap(), std::fs::read(&d2).unwrap());
}

#[test]
fn hash_nonexistent_file_fails() {
    let s = SwtpmSession::new();
    let out = s.tmp().path().join("out.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&out)
        .arg(s.tmp().path().join("nonexistent.bin"))
        .assert()
        .failure();
}
