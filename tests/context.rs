// SPDX-License-Identifier: Apache-2.0
//! Context management tests: contextsave, contextload.

mod common;

use common::SwtpmSession;

#[test]
fn contextsave_and_contextload_roundtrip() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");

    // Save the context to a file.
    let saved = s.tmp().path().join("saved.json");
    s.cmd("contextsave")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-o")
        .arg(&saved)
        .assert()
        .success();
    assert!(std::fs::metadata(&saved).unwrap().len() > 0);

    // Flush the object so the handle is freed.
    s.flush_transient();

    // Reload the context from the saved file.
    let restored = s.tmp().path().join("restored.json");
    s.cmd("contextload")
        .arg("-c")
        .arg(&saved)
        .arg("-o")
        .arg(&restored)
        .assert()
        .success();
    assert!(std::fs::metadata(&restored).unwrap().len() > 0);
}

#[test]
fn contextsave_ecc_key() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_ecc("ecc_primary");

    let saved = s.tmp().path().join("ecc_saved.json");
    s.cmd("contextsave")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-o")
        .arg(&saved)
        .assert()
        .success();
    assert!(std::fs::metadata(&saved).unwrap().len() > 0);
}

#[test]
fn contextload_then_readpublic() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");

    // Read public from original handle.
    let pub_orig = s.tmp().path().join("pub_orig.bin");
    s.cmd("readpublic")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-o")
        .arg(&pub_orig)
        .assert()
        .success();

    // Save and reload.
    let saved = s.tmp().path().join("saved.json");
    s.cmd("contextsave")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("-o")
        .arg(&saved)
        .assert()
        .success();

    s.flush_transient();

    let restored = s.tmp().path().join("restored.json");
    s.cmd("contextload")
        .arg("-c")
        .arg(&saved)
        .arg("-o")
        .arg(&restored)
        .assert()
        .success();

    // Read public from restored context — should match.
    let pub_restored = s.tmp().path().join("pub_restored.bin");
    s.cmd("readpublic")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&restored))
        .arg("-o")
        .arg(&pub_restored)
        .assert()
        .success();

    assert_eq!(
        std::fs::read(&pub_orig).unwrap(),
        std::fs::read(&pub_restored).unwrap()
    );
}
