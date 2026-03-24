// SPDX-License-Identifier: Apache-2.0
//! Sign & verifysignature tests (RSA and ECC) with failure paths.

mod common;

use common::SwtpmSession;

/// Setup helper: creates primary, signing keys, and a hash+ticket for signing.
struct SignSetup {
    session: SwtpmSession,
    rsa_ctx: std::path::PathBuf,
    ecc_ctx: std::path::PathBuf,
    wrong_rsa_ctx: std::path::PathBuf,
    digest_file: std::path::PathBuf,
    ticket_file: std::path::PathBuf,
    msg_file: std::path::PathBuf,
}

impl SignSetup {
    fn new() -> Self {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (rsa_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "sign_rsa");
        let (ecc_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "sign_ecc");
        let (wrong_rsa_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "wrong_rsa");

        let msg_file = s.write_tmp_file("msg.bin", b"test message for signing");
        let digest_file = s.tmp().path().join("digest.bin");
        let ticket_file = s.tmp().path().join("hash_ticket.bin");
        s.cmd("hash")
            .args(["-g", "sha256", "-C", "o", "-o"])
            .arg(&digest_file)
            .arg("-t")
            .arg(&ticket_file)
            .arg(&msg_file)
            .assert()
            .success();

        Self {
            session: s,
            rsa_ctx,
            ecc_ctx,
            wrong_rsa_ctx,
            digest_file,
            ticket_file,
            msg_file,
        }
    }
}

// ── RSA sign & verify ──────────────────────────────────────────────

#[test]
fn rsa_sign_rsassa() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();
    assert!(sig.exists());
}

#[test]
fn rsa_verifysignature() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    let verify_ticket = setup.session.tmp().path().join("verify_ticket.bin");
    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .arg("-d")
        .arg(&setup.digest_file)
        .arg("-s")
        .arg(&sig)
        .arg("-t")
        .arg(&verify_ticket)
        .assert()
        .success();
    assert!(verify_ticket.exists());
}

// ── ECC sign & verify ──────────────────────────────────────────────

#[test]
fn ecc_sign_ecdsa() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_ecc.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ecc_ctx))
        .args(["-g", "sha256", "-s", "ecdsa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();
    assert!(sig.exists());
}

#[test]
fn ecc_verifysignature() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_ecc.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ecc_ctx))
        .args(["-g", "sha256", "-s", "ecdsa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ecc_ctx))
        .arg("-d")
        .arg(&setup.digest_file)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

// ── verifysignature with external key file ──────────────────────────

#[test]
fn verifysignature_with_external_key_file() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    let pub_file = setup.session.tmp().path().join("sign_rsa_pub.bin");
    setup
        .session
        .cmd("readpublic")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .arg("-o")
        .arg(&pub_file)
        .assert()
        .success();

    setup.session.flush_transient();

    setup
        .session
        .cmd("verifysignature")
        .arg("-k")
        .arg(&pub_file)
        .arg("-d")
        .arg(&setup.digest_file)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

// ── verifysignature with message (-m) ──────────────────────────────

#[test]
fn verifysignature_with_message() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-m"])
        .arg(&setup.msg_file)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

// ── verifysignature with message, default hash algorithm ────────────

#[test]
fn verifysignature_with_message_default_hash() {
    // Verify that -m works without explicit -g (uses default sha256).
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .arg("-m")
        .arg(&setup.msg_file)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

// ── Failure: verify with wrong key ──────────────────────────────────

#[test]
fn verifysignature_wrong_key_fails() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.wrong_rsa_ctx))
        .arg("-d")
        .arg(&setup.digest_file)
        .arg("-s")
        .arg(&sig)
        .assert()
        .failure();
}

// ── Failure: verify with wrong digest ───────────────────────────────

#[test]
fn verifysignature_wrong_digest_fails() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    let wrong_msg = setup
        .session
        .write_tmp_file("msg_wrong.bin", b"different message entirely");
    let wrong_digest = setup.session.tmp().path().join("digest_wrong.bin");
    setup
        .session
        .cmd("hash")
        .args(["-g", "sha256", "-o"])
        .arg(&wrong_digest)
        .arg(&wrong_msg)
        .assert()
        .success();

    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .arg("-d")
        .arg(&wrong_digest)
        .arg("-s")
        .arg(&sig)
        .assert()
        .failure();
}

// ── Failure: corrupted signature ────────────────────────────────────

#[test]
fn verifysignature_corrupted_signature_fails() {
    let setup = SignSetup::new();
    let sig = setup.session.tmp().path().join("sig_rsa.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .args(["-g", "sha256", "-s", "rsassa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&sig)
        .assert()
        .success();

    let bad_sig = setup.session.corrupt_file(&sig, "sig_corrupt.bin", 20);

    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .arg("-d")
        .arg(&setup.digest_file)
        .arg("-s")
        .arg(&bad_sig)
        .assert()
        .failure();
}

// ── Failure: ECC sig with RSA key ──────────────────────────────────

#[test]
fn verifysignature_ecc_sig_with_rsa_key_fails() {
    let setup = SignSetup::new();
    let ecc_sig = setup.session.tmp().path().join("sig_ecc.bin");
    setup
        .session
        .cmd("sign")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ecc_ctx))
        .args(["-g", "sha256", "-s", "ecdsa", "-d"])
        .arg(&setup.digest_file)
        .arg("-t")
        .arg(&setup.ticket_file)
        .arg("-o")
        .arg(&ecc_sig)
        .assert()
        .success();

    setup
        .session
        .cmd("verifysignature")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.rsa_ctx))
        .arg("-d")
        .arg(&setup.digest_file)
        .arg("-s")
        .arg(&ecc_sig)
        .assert()
        .failure();
}
