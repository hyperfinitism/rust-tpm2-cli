// SPDX-License-Identifier: Apache-2.0
//! Key lifecycle tests: createprimary, create, load, readpublic,
//! flushcontext, evictcontrol, changeauth, loadexternal.

mod common;

use common::SwtpmSession;

// ── createprimary ───────────────────────────────────────────────────

#[test]
fn createprimary_rsa_owner() {
    let s = SwtpmSession::new();
    let ctx = s.create_primary_rsa("primary");
    assert!(ctx.exists());
}

#[test]
fn createprimary_ecc_owner() {
    let s = SwtpmSession::new();
    let ctx = s.create_primary_ecc("primary_ecc");
    assert!(ctx.exists());
}

#[test]
fn createprimary_with_auth() {
    let s = SwtpmSession::new();
    let ctx = s.tmp().path().join("primary_auth.ctx");
    s.cmd("createprimary")
        .args(["-C", "o", "-G", "rsa", "-p", "parentpass", "-c"])
        .arg(&ctx)
        .assert()
        .success();
    assert!(ctx.exists());
}

#[test]
fn createprimary_endorsement_hierarchy() {
    let s = SwtpmSession::new();
    let ctx = s.tmp().path().join("primary_e.ctx");
    s.cmd("createprimary")
        .args(["-C", "e", "-G", "rsa", "-c"])
        .arg(&ctx)
        .assert()
        .success();
    assert!(ctx.exists());
}

#[test]
fn createprimary_invalid_algorithm_fails() {
    let s = SwtpmSession::new();
    let ctx = s.tmp().path().join("fail.ctx");
    s.cmd("createprimary")
        .args(["-C", "o", "-G", "invalidalg", "-c"])
        .arg(&ctx)
        .assert()
        .failure();
}

// ── readpublic ──────────────────────────────────────────────────────

#[test]
fn readpublic_primary() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let pub_file = s.tmp().path().join("primary_pub.bin");
    s.cmd("readpublic")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .arg("-o")
        .arg(&pub_file)
        .assert()
        .success();
    assert!(std::fs::metadata(&pub_file).unwrap().len() > 0);
}

// ── create (child key) ──────────────────────────────────────────────

#[test]
fn create_rsa_signing_key() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let priv_f = s.tmp().path().join("child.priv");
    let pub_f = s.tmp().path().join("child.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .args(["-G", "rsa", "-g", "sha256", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();
    assert!(priv_f.exists());
    assert!(pub_f.exists());
}

#[test]
fn create_ecc_signing_key() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let priv_f = s.tmp().path().join("child_ecc.priv");
    let pub_f = s.tmp().path().join("child_ecc.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .args(["-G", "ecc", "-g", "sha256", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();
    assert!(priv_f.exists());
    assert!(pub_f.exists());
}

#[test]
fn create_child_key_with_auth() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let priv_f = s.tmp().path().join("child_auth.priv");
    let pub_f = s.tmp().path().join("child_auth.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .args(["-G", "rsa", "-g", "sha256", "-p", "childpass", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();
    assert!(priv_f.exists());
}

#[test]
fn create_hmac_key() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let priv_f = s.tmp().path().join("hmac.priv");
    let pub_f = s.tmp().path().join("hmac.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .args(["-G", "hmac", "-g", "sha256", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();
    assert!(priv_f.exists());
    assert!(pub_f.exists());
}

// ── load ────────────────────────────────────────────────────────────

#[test]
fn load_rsa_child_key() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let (ctx, _, _) = s.create_and_load_signing_key(&primary_ctx, "rsa", "child_rsa");
    assert!(ctx.exists());
}

#[test]
fn load_ecc_child_key() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let (ctx, _, _) = s.create_and_load_signing_key(&primary_ctx, "ecc", "child_ecc");
    assert!(ctx.exists());
}

#[test]
fn load_with_wrong_parent_fails() {
    let s = SwtpmSession::new();
    let rsa_primary = s.create_primary_rsa("primary_rsa");
    let ecc_primary = s.create_primary_ecc("primary_ecc");

    // Create a child under the RSA primary.
    let priv_f = s.tmp().path().join("child.priv");
    let pub_f = s.tmp().path().join("child.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&rsa_primary))
        .args(["-G", "rsa", "-g", "sha256", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();

    // Try to load it under the ECC primary → should fail.
    let bad_ctx = s.tmp().path().join("bad_child.ctx");
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&ecc_primary))
        .arg("-r")
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .arg("-c")
        .arg(&bad_ctx)
        .assert()
        .failure();
}

// ── readpublic on loaded child ──────────────────────────────────────

#[test]
fn readpublic_loaded_child() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("primary");
    let (child_ctx, _, _) = s.create_and_load_signing_key(&primary_ctx, "rsa", "child");
    s.cmd("readpublic")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&child_ctx))
        .assert()
        .success();
}

// ── flushcontext ────────────────────────────────────────────────────

#[test]
fn flushcontext_transient() {
    let s = SwtpmSession::new();
    let _primary = s.create_primary_rsa("primary");
    s.cmd("flushcontext")
        .arg("--transient-object")
        .assert()
        .success();
}

// ── evictcontrol ────────────────────────────────────────────────────

#[test]
fn evictcontrol_persist_and_evict() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("evict_primary");

    // Persist.
    s.cmd("evictcontrol")
        .args(["-C", "o", "-c"])
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .arg("0x81000010")
        .assert()
        .success();

    // Read persistent handle.
    s.cmd("readpublic")
        .args(["-c", "hex:0x81000010"])
        .assert()
        .success();

    // Evict.
    s.cmd("evictcontrol")
        .args(["-C", "o", "-c", "hex:0x81000010", "0x81000010"])
        .assert()
        .success();
}

// ── changeauth ──────────────────────────────────────────────────────

#[test]
fn changeauth_owner_hierarchy() {
    let s = SwtpmSession::new();
    s.cmd("changeauth")
        .args(["--object-hierarchy", "o", "-r", "newpass"])
        .assert()
        .success();
    s.cmd("changeauth")
        .args(["--object-hierarchy", "o", "-p", "newpass", "-r", ""])
        .assert()
        .success();
}

#[test]
fn changeauth_object() {
    let s = SwtpmSession::new();
    let parent_ctx = s.create_primary_rsa("ca_parent");

    let priv_f = s.tmp().path().join("ca.priv");
    let pub_f = s.tmp().path().join("ca.pub");
    s.cmd("create")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&parent_ctx))
        .args(["-G", "rsa", "-g", "sha256", "-p", "old", "-r"])
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .assert()
        .success();

    let ctx = s.tmp().path().join("ca.ctx");
    s.cmd("load")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&parent_ctx))
        .arg("-r")
        .arg(&priv_f)
        .arg("-u")
        .arg(&pub_f)
        .arg("-c")
        .arg(&ctx)
        .assert()
        .success();

    let new_priv = s.tmp().path().join("ca_new.priv");
    s.cmd("changeauth")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&parent_ctx))
        .args(["-p", "old", "-r", "new", "-o"])
        .arg(&new_priv)
        .assert()
        .success();
    assert!(new_priv.exists());
}

// ── loadexternal ────────────────────────────────────────────────────

#[test]
fn loadexternal_public_key() {
    let s = SwtpmSession::new();
    let primary_ctx = s.create_primary_rsa("le_primary");
    let pub_file = s.tmp().path().join("le_pub.bin");
    s.cmd("readpublic")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&primary_ctx))
        .arg("-o")
        .arg(&pub_file)
        .assert()
        .success();

    s.flush_transient();

    let ext_ctx = s.tmp().path().join("le_ext.ctx");
    s.cmd("loadexternal")
        .arg("-u")
        .arg(&pub_file)
        .args(["-a", "n", "-c"])
        .arg(&ext_ctx)
        .assert()
        .success();
    assert!(ext_ctx.exists());
}
