// SPDX-License-Identifier: Apache-2.0
//! NV storage tests: nvdefine, nvwrite, nvread, nvreadpublic, nvundefine,
//! nvincrement (counter), nvsetbits (bitfield), nvextend (PCR-like),
//! nvreadlock, nvwritelock.

mod common;

use common::SwtpmSession;

const NV_IDX: &str = "0x01000001";
const NV_IDX2: &str = "0x01000002";
const NV_COUNTER: &str = "0x01000003";
const NV_BITS: &str = "0x01000004";
const NV_EXTEND: &str = "0x01000005";
const NV_RLOCK: &str = "0x01000006";
const NV_WLOCK: &str = "0x01000007";

#[test]
fn nvdefine_ordinary() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "32", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();
}

#[test]
fn nvreadpublic() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "32", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();
    s.cmd("nvreadpublic").arg(NV_IDX).assert().success();
}

#[test]
fn nvwrite_and_read_roundtrip() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "32", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();

    let data = b"hello world, nv storage!12345678";
    let data_file = s.write_tmp_file("nv_data.bin", data);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data_file)
        .arg(NV_IDX)
        .assert()
        .success();

    let read_file = s.tmp().path().join("nv_read.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-s", "32", "-o"])
        .arg(&read_file)
        .arg(NV_IDX)
        .assert()
        .success();

    assert_eq!(std::fs::read(&read_file).unwrap(), data);
}

#[test]
fn nvread_auto_size() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "32", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();

    let data = b"hello world, nv storage!12345678";
    let data_file = s.write_tmp_file("nv_data.bin", data);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data_file)
        .arg(NV_IDX)
        .assert()
        .success();

    let read_file = s.tmp().path().join("nv_read.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&read_file)
        .arg(NV_IDX)
        .assert()
        .success();
    assert_eq!(std::fs::read(&read_file).unwrap().len(), 32);
}

#[test]
fn nvundefine() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "32", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();
    s.cmd("nvundefine")
        .args(["-C", "o", NV_IDX])
        .assert()
        .success();
}

#[test]
fn nvread_after_undefine_fails() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "32", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();
    s.cmd("nvundefine")
        .args(["-C", "o", NV_IDX])
        .assert()
        .success();
    s.cmd("nvread")
        .args(["-C", "o", "-s", "32", NV_IDX])
        .assert()
        .failure();
}

#[test]
fn nvdefine_with_auth() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "16",
            "-a",
            "ownerwrite|ownerread",
            "-p",
            "nvpass",
            NV_IDX2,
        ])
        .assert()
        .success();
    s.cmd("nvundefine")
        .args(["-C", "o", NV_IDX2])
        .assert()
        .success();
}

#[test]
fn nvwrite_overwrite_read() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "8", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();

    let data_a = s.write_tmp_file("a.bin", b"AAAAAAAA");
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data_a)
        .arg(NV_IDX)
        .assert()
        .success();

    let data_b = s.write_tmp_file("b.bin", b"BBBBBBBB");
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data_b)
        .arg(NV_IDX)
        .assert()
        .success();

    let read_file = s.tmp().path().join("nv_read.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&read_file)
        .arg(NV_IDX)
        .assert()
        .success();

    assert_eq!(std::fs::read(&read_file).unwrap(), b"BBBBBBBB");
}

#[test]
fn nvdefine_duplicate_fails() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "16", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .success();
    s.cmd("nvdefine")
        .args(["-C", "o", "-s", "16", "-a", "ownerwrite|ownerread", NV_IDX])
        .assert()
        .failure();
    // Cleanup.
    let _ = s.cmd("nvundefine").args(["-C", "o", NV_IDX]).ok();
}

// ════════════════════════════════════════════════════════════════════
// NV Counter (nt=counter) + nvincrement
// ════════════════════════════════════════════════════════════════════

#[test]
fn nv_counter_define_and_increment() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "nt=counter|ownerwrite|ownerread",
            NV_COUNTER,
        ])
        .assert()
        .success();

    // First increment initializes the counter.
    s.cmd("nvincrement")
        .args(["-C", "o", NV_COUNTER])
        .assert()
        .success();

    let out1 = s.tmp().path().join("counter1.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out1)
        .arg(NV_COUNTER)
        .assert()
        .success();
    let val1 = std::fs::read(&out1).unwrap();
    assert_eq!(val1.len(), 8, "counter should be 8 bytes (u64)");

    // Second increment should produce a different (higher) value.
    s.cmd("nvincrement")
        .args(["-C", "o", NV_COUNTER])
        .assert()
        .success();

    let out2 = s.tmp().path().join("counter2.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out2)
        .arg(NV_COUNTER)
        .assert()
        .success();
    let val2 = std::fs::read(&out2).unwrap();

    // Counter must have increased.
    let c1 = u64::from_be_bytes(val1.try_into().unwrap());
    let c2 = u64::from_be_bytes(val2.try_into().unwrap());
    assert_eq!(c2, c1 + 1, "counter should increment by 1");

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_COUNTER]).ok();
}

#[test]
fn nv_counter_monotonic_across_multiple_increments() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "nt=counter|ownerwrite|ownerread",
            NV_COUNTER,
        ])
        .assert()
        .success();

    // Increment 5 times.
    for _ in 0..5 {
        s.cmd("nvincrement")
            .args(["-C", "o", NV_COUNTER])
            .assert()
            .success();
    }

    let out = s.tmp().path().join("counter.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(NV_COUNTER)
        .assert()
        .success();
    let val = u64::from_be_bytes(std::fs::read(&out).unwrap().try_into().unwrap());

    // Increment once more.
    s.cmd("nvincrement")
        .args(["-C", "o", NV_COUNTER])
        .assert()
        .success();

    let out2 = s.tmp().path().join("counter2.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out2)
        .arg(NV_COUNTER)
        .assert()
        .success();
    let val2 = u64::from_be_bytes(std::fs::read(&out2).unwrap().try_into().unwrap());

    assert_eq!(val2, val + 1);

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_COUNTER]).ok();
}

#[test]
fn nv_counter_write_fails() {
    // Regular nvwrite should fail on a counter index.
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "nt=counter|ownerwrite|ownerread",
            NV_COUNTER,
        ])
        .assert()
        .success();

    // Must increment first for TPMA_NV_WRITTEN.
    s.cmd("nvincrement")
        .args(["-C", "o", NV_COUNTER])
        .assert()
        .success();

    let data = s.write_tmp_file("data.bin", &[0u8; 8]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_COUNTER)
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_COUNTER]).ok();
}

// ════════════════════════════════════════════════════════════════════
// NV Bitfield (nt=bits) + nvsetbits
// ════════════════════════════════════════════════════════════════════

#[test]
fn nv_bits_define_and_setbits() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "nt=bits|ownerwrite|ownerread",
            NV_BITS,
        ])
        .assert()
        .success();

    // Set bit 0.
    s.cmd("nvsetbits")
        .args(["-C", "o", "-i", "0x0000000000000001", NV_BITS])
        .assert()
        .success();

    let out = s.tmp().path().join("bits1.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(NV_BITS)
        .assert()
        .success();
    let val = u64::from_be_bytes(std::fs::read(&out).unwrap().try_into().unwrap());
    assert_eq!(val & 1, 1, "bit 0 should be set");

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_BITS]).ok();
}

#[test]
fn nv_bits_accumulate() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "nt=bits|ownerwrite|ownerread",
            NV_BITS,
        ])
        .assert()
        .success();

    // Set bit 0.
    s.cmd("nvsetbits")
        .args(["-C", "o", "-i", "0x0000000000000001", NV_BITS])
        .assert()
        .success();

    // Set bit 4.
    s.cmd("nvsetbits")
        .args(["-C", "o", "-i", "0x0000000000000010", NV_BITS])
        .assert()
        .success();

    let out = s.tmp().path().join("bits.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(NV_BITS)
        .assert()
        .success();
    let val = u64::from_be_bytes(std::fs::read(&out).unwrap().try_into().unwrap());
    // Both bit 0 and bit 4 should be set.
    assert_eq!(
        val & 0x11,
        0x11,
        "bits 0 and 4 should be set (OR accumulation)"
    );

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_BITS]).ok();
}

#[test]
fn nv_bits_cannot_clear() {
    // Once bits are set, they cannot be cleared (only OR'd).
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "nt=bits|ownerwrite|ownerread",
            NV_BITS,
        ])
        .assert()
        .success();

    // Set bits 0xFF.
    s.cmd("nvsetbits")
        .args(["-C", "o", "-i", "0x00000000000000FF", NV_BITS])
        .assert()
        .success();

    // Set with 0x00 (attempting to "clear").
    s.cmd("nvsetbits")
        .args(["-C", "o", "-i", "0x0000000000000000", NV_BITS])
        .assert()
        .success();

    // Value should still be 0xFF.
    let out = s.tmp().path().join("bits.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(NV_BITS)
        .assert()
        .success();
    let val = u64::from_be_bytes(std::fs::read(&out).unwrap().try_into().unwrap());
    assert_eq!(val & 0xFF, 0xFF, "bits cannot be cleared by OR with 0");

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_BITS]).ok();
}

#[test]
fn nv_bits_write_fails() {
    // Regular nvwrite should fail on a bits index.
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "8",
            "-a",
            "nt=bits|ownerwrite|ownerread",
            NV_BITS,
        ])
        .assert()
        .success();

    let data = s.write_tmp_file("data.bin", &[0u8; 8]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_BITS)
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_BITS]).ok();
}

// ════════════════════════════════════════════════════════════════════
// NV Extend (nt=extend) + nvextend
// ════════════════════════════════════════════════════════════════════

#[test]
fn nv_extend_define_and_extend() {
    let s = SwtpmSession::new();
    // Size must match hash digest length. SHA-256 = 32 bytes.
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "32",
            "-g",
            "sha256",
            "-a",
            "nt=extend|ownerwrite|ownerread",
            NV_EXTEND,
        ])
        .assert()
        .success();

    // Extend with some data.
    let data = s.write_tmp_file("extend_data.bin", b"hello extend");
    s.cmd("nvextend")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_EXTEND)
        .assert()
        .success();

    // Read: should be non-zero (hash of initial zeros || data).
    let out = s.tmp().path().join("extend_val.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(NV_EXTEND)
        .assert()
        .success();
    let val = std::fs::read(&out).unwrap();
    assert_eq!(val.len(), 32);
    assert_ne!(val, vec![0u8; 32], "extended NV should be non-zero");

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_EXTEND]).ok();
}

#[test]
fn nv_extend_is_deterministic() {
    // Extending with the same data from the same initial state → same result.
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "32",
            "-g",
            "sha256",
            "-a",
            "nt=extend|ownerwrite|ownerread",
            NV_EXTEND,
        ])
        .assert()
        .success();

    let data = s.write_tmp_file("data.bin", b"deterministic");
    s.cmd("nvextend")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_EXTEND)
        .assert()
        .success();

    let out1 = s.tmp().path().join("val1.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out1)
        .arg(NV_EXTEND)
        .assert()
        .success();

    // Undefine/redefine and extend with same data.
    s.cmd("nvundefine")
        .args(["-C", "o", NV_EXTEND])
        .assert()
        .success();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "32",
            "-g",
            "sha256",
            "-a",
            "nt=extend|ownerwrite|ownerread",
            NV_EXTEND,
        ])
        .assert()
        .success();
    s.cmd("nvextend")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_EXTEND)
        .assert()
        .success();

    let out2 = s.tmp().path().join("val2.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out2)
        .arg(NV_EXTEND)
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "same extend data from same initial state must produce same result"
    );

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_EXTEND]).ok();
}

#[test]
fn nv_extend_different_data_different_result() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "32",
            "-g",
            "sha256",
            "-a",
            "nt=extend|ownerwrite|ownerread",
            NV_EXTEND,
        ])
        .assert()
        .success();

    let data_a = s.write_tmp_file("a.bin", b"data_a");
    s.cmd("nvextend")
        .args(["-C", "o", "-i"])
        .arg(&data_a)
        .arg(NV_EXTEND)
        .assert()
        .success();

    let out_a = s.tmp().path().join("val_a.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out_a)
        .arg(NV_EXTEND)
        .assert()
        .success();

    // Undefine, redefine, extend with different data.
    s.cmd("nvundefine")
        .args(["-C", "o", NV_EXTEND])
        .assert()
        .success();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "32",
            "-g",
            "sha256",
            "-a",
            "nt=extend|ownerwrite|ownerread",
            NV_EXTEND,
        ])
        .assert()
        .success();

    let data_b = s.write_tmp_file("b.bin", b"data_b");
    s.cmd("nvextend")
        .args(["-C", "o", "-i"])
        .arg(&data_b)
        .arg(NV_EXTEND)
        .assert()
        .success();

    let out_b = s.tmp().path().join("val_b.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out_b)
        .arg(NV_EXTEND)
        .assert()
        .success();

    assert_ne!(
        std::fs::read(&out_a).unwrap(),
        std::fs::read(&out_b).unwrap(),
        "different extend data must produce different results"
    );
}

#[test]
fn nv_extend_accumulates() {
    // Two sequential extends produce a different result than one extend.
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "32",
            "-g",
            "sha256",
            "-a",
            "nt=extend|ownerwrite|ownerread",
            NV_EXTEND,
        ])
        .assert()
        .success();

    let data = s.write_tmp_file("data.bin", b"hello");
    s.cmd("nvextend")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_EXTEND)
        .assert()
        .success();

    let out1 = s.tmp().path().join("val_after_1.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out1)
        .arg(NV_EXTEND)
        .assert()
        .success();

    // Extend again with the same data.
    s.cmd("nvextend")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_EXTEND)
        .assert()
        .success();

    let out2 = s.tmp().path().join("val_after_2.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out2)
        .arg(NV_EXTEND)
        .assert()
        .success();

    assert_ne!(
        std::fs::read(&out1).unwrap(),
        std::fs::read(&out2).unwrap(),
        "second extend must change the value"
    );

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_EXTEND]).ok();
}

#[test]
fn nv_extend_write_fails() {
    // Regular nvwrite should fail on an extend index.
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "32",
            "-g",
            "sha256",
            "-a",
            "nt=extend|ownerwrite|ownerread",
            NV_EXTEND,
        ])
        .assert()
        .success();

    let data = s.write_tmp_file("data.bin", &[0u8; 32]);
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_EXTEND)
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_EXTEND]).ok();
}

// ════════════════════════════════════════════════════════════════════
// NV Read Lock + Write Lock
// ════════════════════════════════════════════════════════════════════

#[test]
fn nv_readlock_prevents_read() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "16",
            "-a",
            "ownerwrite|ownerread|read_stclear",
            NV_RLOCK,
        ])
        .assert()
        .success();

    // Write some data.
    let data = s.write_tmp_file("data.bin", b"lock test data!!");
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_RLOCK)
        .assert()
        .success();

    // Verify read works before locking.
    let out = s.tmp().path().join("read_before.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(NV_RLOCK)
        .assert()
        .success();

    // Lock for reading.
    s.cmd("nvreadlock")
        .args(["-C", "o", NV_RLOCK])
        .assert()
        .success();

    // Read should now fail.
    s.cmd("nvread")
        .args(["-C", "o", "-s", "16", NV_RLOCK])
        .assert()
        .failure();

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_RLOCK]).ok();
}

#[test]
fn nv_writelock_prevents_write() {
    let s = SwtpmSession::new();
    s.cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "16",
            "-a",
            "ownerwrite|ownerread|writedefine",
            NV_WLOCK,
        ])
        .assert()
        .success();

    // Write some data first.
    let data = s.write_tmp_file("data.bin", b"lock test data!!");
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data)
        .arg(NV_WLOCK)
        .assert()
        .success();

    // Lock for writing.
    s.cmd("nvwritelock")
        .args(["-C", "o", NV_WLOCK])
        .assert()
        .success();

    // Write should now fail.
    let data2 = s.write_tmp_file("data2.bin", b"new data!!!!!!!!");
    s.cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&data2)
        .arg(NV_WLOCK)
        .assert()
        .failure();

    // Read should still work.
    let out = s.tmp().path().join("read_after_wlock.bin");
    s.cmd("nvread")
        .args(["-C", "o", "-o"])
        .arg(&out)
        .arg(NV_WLOCK)
        .assert()
        .success();
    assert_eq!(std::fs::read(&out).unwrap(), b"lock test data!!");

    let _ = s.cmd("nvundefine").args(["-C", "o", NV_WLOCK]).ok();
}
