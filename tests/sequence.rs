// SPDX-License-Identifier: Apache-2.0
//! Sequence operation tests: hashsequencestart, hmacsequencestart,
//! sequenceupdate, sequencecomplete.

mod common;

use common::SwtpmSession;

// ── Hash sequence ──────────────────────────────────────────────────

#[test]
fn hash_sequence_sha256_matches_single_hash() {
    let s = SwtpmSession::new();
    let data = s.write_tmp_file("data.bin", b"hello world");

    // Compute hash in one shot for reference.
    let expected = s.tmp().path().join("expected.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&expected)
        .arg(&data)
        .assert()
        .success();

    // Compute the same hash via the sequence API.
    let seq_ctx = s.tmp().path().join("seq.ctx");
    s.cmd("hashsequencestart")
        .args(["-g", "sha256", "-o"])
        .arg(&seq_ctx)
        .assert()
        .success();

    s.cmd("sequenceupdate")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-i")
        .arg(&data)
        .assert()
        .success();

    let result = s.tmp().path().join("result.bin");
    s.cmd("sequencecomplete")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-o")
        .arg(&result)
        .args(["-C", "n"])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&expected).unwrap(),
        std::fs::read(&result).unwrap()
    );
}

#[test]
fn hash_sequence_multiple_updates() {
    let s = SwtpmSession::new();

    // Split "hello world" across two updates.
    let part1 = s.write_tmp_file("part1.bin", b"hello ");
    let part2 = s.write_tmp_file("part2.bin", b"world");

    // Reference hash of the full data.
    let full = s.write_tmp_file("full.bin", b"hello world");
    let expected = s.tmp().path().join("expected.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&expected)
        .arg(&full)
        .assert()
        .success();

    // Sequence with two updates.
    let seq_ctx = s.tmp().path().join("seq.ctx");
    s.cmd("hashsequencestart")
        .args(["-g", "sha256", "-o"])
        .arg(&seq_ctx)
        .assert()
        .success();

    s.cmd("sequenceupdate")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-i")
        .arg(&part1)
        .assert()
        .success();

    s.cmd("sequenceupdate")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-i")
        .arg(&part2)
        .assert()
        .success();

    let result = s.tmp().path().join("result.bin");
    s.cmd("sequencecomplete")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-o")
        .arg(&result)
        .args(["-C", "n"])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&expected).unwrap(),
        std::fs::read(&result).unwrap()
    );
}

#[test]
fn hash_sequence_with_final_data_in_complete() {
    let s = SwtpmSession::new();

    let part1 = s.write_tmp_file("part1.bin", b"hello ");
    let part2 = s.write_tmp_file("part2.bin", b"world");

    let full = s.write_tmp_file("full.bin", b"hello world");
    let expected = s.tmp().path().join("expected.bin");
    s.cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&expected)
        .arg(&full)
        .assert()
        .success();

    let seq_ctx = s.tmp().path().join("seq.ctx");
    s.cmd("hashsequencestart")
        .args(["-g", "sha256", "-o"])
        .arg(&seq_ctx)
        .assert()
        .success();

    s.cmd("sequenceupdate")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-i")
        .arg(&part1)
        .assert()
        .success();

    // Provide the remaining data via sequencecomplete's -i flag.
    let result = s.tmp().path().join("result.bin");
    s.cmd("sequencecomplete")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-i")
        .arg(&part2)
        .arg("-o")
        .arg(&result)
        .args(["-C", "n"])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&expected).unwrap(),
        std::fs::read(&result).unwrap()
    );
}

#[test]
fn hash_sequence_produces_ticket() {
    let s = SwtpmSession::new();
    let data = s.write_tmp_file("data.bin", b"ticket test");

    let seq_ctx = s.tmp().path().join("seq.ctx");
    s.cmd("hashsequencestart")
        .args(["-g", "sha256", "-o"])
        .arg(&seq_ctx)
        .assert()
        .success();

    s.cmd("sequenceupdate")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-i")
        .arg(&data)
        .assert()
        .success();

    let result = s.tmp().path().join("result.bin");
    let ticket = s.tmp().path().join("ticket.bin");
    s.cmd("sequencecomplete")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-o")
        .arg(&result)
        .arg("-t")
        .arg(&ticket)
        .args(["-C", "o"])
        .assert()
        .success();

    assert!(std::fs::metadata(&result).unwrap().len() > 0);
    assert!(std::fs::metadata(&ticket).unwrap().len() > 0);
}

// ── HMAC sequence ──────────────────────────────────────────────────

#[test]
fn hmac_sequence_matches_single_hmac() {
    let s = SwtpmSession::new();
    let data = s.write_tmp_file("data.bin", b"hmac sequence test");

    // Create an HMAC key.
    let primary = s.create_primary_rsa("primary");
    let hmac_priv = s.tmp().path().join("hmac.priv");
    let hmac_pub = s.tmp().path().join("hmac.pub");
    let hmac_ctx = s.tmp().path().join("hmac.ctx");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .args(["-G", "hmac", "-g", "sha256", "-r"])
        .arg(&hmac_priv)
        .arg("-u")
        .arg(&hmac_pub)
        .assert()
        .success();
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-r")
        .arg(&hmac_priv)
        .arg("-u")
        .arg(&hmac_pub)
        .arg("-c")
        .arg(&hmac_ctx)
        .assert()
        .success();

    // Compute HMAC in one shot for reference.
    let expected = s.tmp().path().join("expected.bin");
    s.cmd("hmac")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&hmac_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&expected)
        .arg("-i")
        .arg(&data)
        .assert()
        .success();

    // Compute the same HMAC via the sequence API.
    let seq_ctx = s.tmp().path().join("hmac_seq.ctx");
    s.cmd("hmacsequencestart")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&hmac_ctx))
        .args(["-g", "sha256", "-o"])
        .arg(&seq_ctx)
        .assert()
        .success();

    s.cmd("sequenceupdate")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-i")
        .arg(&data)
        .assert()
        .success();

    let result = s.tmp().path().join("hmac_result.bin");
    s.cmd("sequencecomplete")
        .arg("-c")
        .arg(&seq_ctx)
        .arg("-o")
        .arg(&result)
        .args(["-C", "n"])
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&expected).unwrap(),
        std::fs::read(&result).unwrap()
    );
}
