// SPDX-License-Identifier: Apache-2.0
//! PCR operation tests: pcrread, pcrextend, pcrreset with value verification.

mod common;

use common::SwtpmSession;
use sha2::{Digest, Sha256};

#[test]
fn pcrread_sha256_selected() {
    let s = SwtpmSession::new();
    s.cmd("pcrread").arg("sha256:0,1,2").assert().success();
}

#[test]
fn pcrread_all_sha256() {
    let s = SwtpmSession::new();
    s.cmd("pcrread").arg("sha256:all").assert().success();
}

#[test]
fn pcrread_to_file() {
    let s = SwtpmSession::new();
    let out = s.tmp().path().join("pcr0.bin");
    s.cmd("pcrread")
        .arg("sha256:0")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    assert!(out.exists());
    assert!(std::fs::metadata(&out).unwrap().len() > 0);
}

#[test]
fn pcrextend_changes_value() {
    let s = SwtpmSession::new();
    let digest = "0000000000000000000000000000000000000000000000000000000000000001";
    s.cmd("pcrextend")
        .arg(format!("16:sha256={digest}"))
        .assert()
        .success();

    let out = s.tmp().path().join("pcr16.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    let data = std::fs::read(&out).unwrap();
    assert_ne!(data, vec![0u8; 32], "PCR should be non-zero after extend");
}

#[test]
fn pcrextend_twice_changes_value() {
    let s = SwtpmSession::new();
    let digest1 = "0000000000000000000000000000000000000000000000000000000000000001";
    s.cmd("pcrextend")
        .arg(format!("16:sha256={digest1}"))
        .assert()
        .success();

    let before = s.tmp().path().join("before.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&before)
        .assert()
        .success();

    let digest2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    s.cmd("pcrextend")
        .arg(format!("16:sha256={digest2}"))
        .assert()
        .success();

    let after = s.tmp().path().join("after.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&after)
        .assert()
        .success();

    assert_ne!(
        std::fs::read(&before).unwrap(),
        std::fs::read(&after).unwrap()
    );
}

#[test]
fn pcrreset_zeros_pcr() {
    let s = SwtpmSession::new();
    // Extend first to make it non-zero.
    let digest = "0000000000000000000000000000000000000000000000000000000000000001";
    s.cmd("pcrextend")
        .arg(format!("16:sha256={digest}"))
        .assert()
        .success();

    s.cmd("pcrreset").arg("16").assert().success();

    let out = s.tmp().path().join("pcr16_reset.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    assert_eq!(std::fs::read(&out).unwrap(), vec![0u8; 32]);
}

#[test]
fn pcrextend_computed_value_matches() {
    let s = SwtpmSession::new();
    // Reset PCR 16 to zeros.
    s.cmd("pcrreset").arg("16").assert().success();

    let extend_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    s.cmd("pcrextend")
        .arg(format!("16:sha256={extend_hex}"))
        .assert()
        .success();

    let out = s.tmp().path().join("pcr16.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    // Compute expected: SHA-256(32_zero_bytes || extend_digest_bytes)
    let old_pcr = [0u8; 32];
    let extend_bytes = hex::decode(extend_hex).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(old_pcr);
    hasher.update(&extend_bytes);
    let expected = hasher.finalize();

    assert_eq!(std::fs::read(&out).unwrap(), expected.as_slice());
}

// ── pcrevent ────────────────────────────────────────────────────────

#[test]
fn pcrevent_extends_pcr() {
    let s = SwtpmSession::new();
    s.cmd("pcrreset").arg("16").assert().success();

    let event_data = s.write_tmp_file("event.bin", b"boot event data");
    s.cmd("pcrevent")
        .arg("16")
        .arg("-i")
        .arg(&event_data)
        .assert()
        .success();

    let out = s.tmp().path().join("pcr16.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();
    assert_ne!(
        std::fs::read(&out).unwrap(),
        vec![0u8; 32],
        "PCR should be non-zero after pcrevent"
    );
}

#[test]
fn pcrevent_is_deterministic() {
    let s = SwtpmSession::new();
    s.cmd("pcrreset").arg("16").assert().success();

    let event_data = s.write_tmp_file("event.bin", b"deterministic event");
    s.cmd("pcrevent")
        .arg("16")
        .arg("-i")
        .arg(&event_data)
        .assert()
        .success();

    let out1 = s.tmp().path().join("pcr16_1.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out1)
        .assert()
        .success();

    // Reset and extend again with same data.
    s.cmd("pcrreset").arg("16").assert().success();
    s.cmd("pcrevent")
        .arg("16")
        .arg("-i")
        .arg(&event_data)
        .assert()
        .success();

    let out2 = s.tmp().path().join("pcr16_2.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out2)
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "pcrevent with same data from same state must produce same PCR value"
    );
}

#[test]
fn pcrevent_different_data_different_result() {
    let s = SwtpmSession::new();
    s.cmd("pcrreset").arg("16").assert().success();

    let data_a = s.write_tmp_file("a.bin", b"event_a");
    s.cmd("pcrevent")
        .arg("16")
        .arg("-i")
        .arg(&data_a)
        .assert()
        .success();

    let out_a = s.tmp().path().join("pcr_a.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out_a)
        .assert()
        .success();

    s.cmd("pcrreset").arg("16").assert().success();

    let data_b = s.write_tmp_file("b.bin", b"event_b");
    s.cmd("pcrevent")
        .arg("16")
        .arg("-i")
        .arg(&data_b)
        .assert()
        .success();

    let out_b = s.tmp().path().join("pcr_b.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
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
fn pcrevent_computed_value_matches() {
    // pcrevent hashes the data first, then extends: PCR = H(old || H(data))
    let s = SwtpmSession::new();
    s.cmd("pcrreset").arg("16").assert().success();

    let event_data = b"compute me";
    let data_file = s.write_tmp_file("event.bin", event_data);
    s.cmd("pcrevent")
        .arg("16")
        .arg("-i")
        .arg(&data_file)
        .assert()
        .success();

    let out = s.tmp().path().join("pcr16.bin");
    s.cmd("pcrread")
        .arg("sha256:16")
        .arg("-o")
        .arg(&out)
        .assert()
        .success();

    // Expected: SHA-256(zeros_32 || SHA-256(event_data))
    let data_hash = Sha256::digest(event_data);
    let mut hasher = Sha256::new();
    hasher.update([0u8; 32]);
    hasher.update(data_hash);
    let expected = hasher.finalize();

    assert_eq!(std::fs::read(&out).unwrap(), expected.as_slice());
}
