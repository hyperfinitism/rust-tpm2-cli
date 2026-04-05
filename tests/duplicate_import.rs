// SPDX-License-Identifier: Apache-2.0
//! Duplicate/import tests: verify duplicate fails on non-duplicatable keys
//! (the CLI creates keys with fixedTPM|fixedParent by default).

mod common;

use common::SwtpmSession;

#[test]
fn duplicate_fixed_key_fails() {
    let s = SwtpmSession::new();

    let parent = s.create_primary_rsa("parent");
    let (child_ctx, _, _) = s.create_and_load_signing_key(&parent, "rsa", "child");

    // Keys created via `create` have fixedTPM|fixedParent, so duplicate
    // must fail with TPM_RC_ATTRIBUTES.
    let dup_priv = s.tmp().path().join("dup.priv");
    let dup_seed = s.tmp().path().join("dup.seed");
    s.cmd("duplicate")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&child_ctx))
        .arg("--parent-context-null")
        .arg("-G")
        .arg("null")
        .arg("-r")
        .arg(&dup_priv)
        .arg("-s")
        .arg(&dup_seed)
        .assert()
        .failure();
}

#[test]
fn duplicate_primary_key_fails() {
    let s = SwtpmSession::new();
    let primary = s.create_primary_rsa("primary");

    let dup_priv = s.tmp().path().join("dup.priv");
    let dup_seed = s.tmp().path().join("dup.seed");
    s.cmd("duplicate")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary))
        .arg("--parent-context-null")
        .arg("-G")
        .arg("null")
        .arg("-r")
        .arg(&dup_priv)
        .arg("-s")
        .arg(&dup_seed)
        .assert()
        .failure();
}
