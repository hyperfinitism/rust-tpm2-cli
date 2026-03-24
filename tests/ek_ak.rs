// SPDX-License-Identifier: Apache-2.0
//! EK/AK and credential tests: createek, createak, makecredential, activatecredential.

mod common;

use common::SwtpmSession;

#[test]
fn createek_rsa() {
    let s = SwtpmSession::new();
    let ek_ctx = s.tmp().path().join("ek.ctx");
    let ek_pub = s.tmp().path().join("ek_pub.bin");
    s.cmd("createek")
        .args(["-G", "rsa", "-c"])
        .arg(&ek_ctx)
        .arg("-u")
        .arg(&ek_pub)
        .assert()
        .success();
    assert!(ek_pub.exists());
}

#[test]
fn createek_ecc() {
    let s = SwtpmSession::new();
    let ek_ctx = s.tmp().path().join("ek_ecc.ctx");
    s.cmd("createek")
        .args(["-G", "ecc", "-c"])
        .arg(&ek_ctx)
        .assert()
        .success();
    assert!(ek_ctx.exists());
}

#[test]
fn createak_rsa() {
    let s = SwtpmSession::new();
    let ek_ctx = s.tmp().path().join("ek.ctx");
    let ek_pub = s.tmp().path().join("ek_pub.bin");
    s.cmd("createek")
        .args(["-G", "rsa", "-c"])
        .arg(&ek_ctx)
        .arg("-u")
        .arg(&ek_pub)
        .assert()
        .success();

    s.flush_transient();

    let ak_ctx = s.tmp().path().join("ak.ctx");
    let ak_pub = s.tmp().path().join("ak_pub.bin");
    let ak_priv = s.tmp().path().join("ak_priv.bin");
    let ak_name = s.tmp().path().join("ak_name.bin");
    s.cmd("createak")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&ek_ctx))
        .arg("-c")
        .arg(&ak_ctx)
        .args(["-G", "rsa", "-g", "sha256", "-u"])
        .arg(&ak_pub)
        .arg("-r")
        .arg(&ak_priv)
        .arg("-n")
        .arg(&ak_name)
        .assert()
        .success();
    assert!(ak_pub.exists());
    assert!(ak_name.exists());
}

#[test]
fn makecredential_and_activatecredential_roundtrip() {
    let s = SwtpmSession::new();
    let ek_ctx = s.tmp().path().join("ek.ctx");
    let ek_pub = s.tmp().path().join("ek_pub.bin");
    s.cmd("createek")
        .args(["-G", "rsa", "-c"])
        .arg(&ek_ctx)
        .arg("-u")
        .arg(&ek_pub)
        .assert()
        .success();

    s.flush_transient();

    let ak_ctx = s.tmp().path().join("ak.ctx");
    let ak_pub = s.tmp().path().join("ak_pub.bin");
    let ak_priv = s.tmp().path().join("ak_priv.bin");
    let ak_name = s.tmp().path().join("ak_name.bin");
    s.cmd("createak")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&ek_ctx))
        .arg("-c")
        .arg(&ak_ctx)
        .args(["-G", "rsa", "-g", "sha256", "-u"])
        .arg(&ak_pub)
        .arg("-r")
        .arg(&ak_priv)
        .arg("-n")
        .arg(&ak_name)
        .assert()
        .success();

    let secret = s.write_tmp_file("secret.bin", b"secret credential!");
    let cred_blob = s.tmp().path().join("cred_blob.bin");
    s.cmd("makecredential")
        .arg("-u")
        .arg(&ek_pub)
        .arg("-s")
        .arg(&secret)
        .arg("-n")
        .arg(&ak_name)
        .arg("-o")
        .arg(&cred_blob)
        .assert()
        .success();
    assert!(cred_blob.exists());

    let certinfo = s.tmp().path().join("certinfo.bin");
    s.cmd("activatecredential")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ak_ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&ek_ctx))
        .arg("-i")
        .arg(&cred_blob)
        .arg("-o")
        .arg(&certinfo)
        .assert()
        .success();

    assert_eq!(std::fs::read(&certinfo).unwrap(), b"secret credential!");
}

#[test]
fn activatecredential_corrupted_blob_fails() {
    let s = SwtpmSession::new();
    let ek_ctx = s.tmp().path().join("ek.ctx");
    let ek_pub = s.tmp().path().join("ek_pub.bin");
    s.cmd("createek")
        .args(["-G", "rsa", "-c"])
        .arg(&ek_ctx)
        .arg("-u")
        .arg(&ek_pub)
        .assert()
        .success();

    s.flush_transient();

    let ak_ctx = s.tmp().path().join("ak.ctx");
    let ak_pub = s.tmp().path().join("ak_pub.bin");
    let ak_priv = s.tmp().path().join("ak_priv.bin");
    let ak_name = s.tmp().path().join("ak_name.bin");
    s.cmd("createak")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&ek_ctx))
        .arg("-c")
        .arg(&ak_ctx)
        .args(["-G", "rsa", "-g", "sha256", "-u"])
        .arg(&ak_pub)
        .arg("-r")
        .arg(&ak_priv)
        .arg("-n")
        .arg(&ak_name)
        .assert()
        .success();

    let secret = s.write_tmp_file("secret.bin", b"secret credential!");
    let cred_blob = s.tmp().path().join("cred_blob.bin");
    s.cmd("makecredential")
        .arg("-u")
        .arg(&ek_pub)
        .arg("-s")
        .arg(&secret)
        .arg("-n")
        .arg(&ak_name)
        .arg("-o")
        .arg(&cred_blob)
        .assert()
        .success();

    let bad_blob = s.corrupt_file(&cred_blob, "cred_blob_bad.bin", 10);

    s.cmd("activatecredential")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ak_ctx))
        .arg("-C")
        .arg(SwtpmSession::file_ref(&ek_ctx))
        .arg("-i")
        .arg(&bad_blob)
        .arg("-o")
        .arg(s.tmp().path().join("certinfo_bad.bin"))
        .assert()
        .failure();
}
