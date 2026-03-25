// SPDX-License-Identifier: Apache-2.0
//! Attestation tests: quote, checkquote with comprehensive verification
//! and 8+ failure-path tests.

mod common;

use common::SwtpmSession;

/// Setup helper for attestation tests.
struct AttestSetup {
    s: SwtpmSession,
    primary_ctx: std::path::PathBuf,
    ak_ctx: std::path::PathBuf,
    ak_pub: std::path::PathBuf,
    ak_priv: std::path::PathBuf,
    ak_tpmt: std::path::PathBuf,
    wrong_ak_tpmt: std::path::PathBuf,
    nonce: std::path::PathBuf,
}

impl AttestSetup {
    fn new() -> Self {
        let s = SwtpmSession::new();
        let primary_ctx = s.create_primary_rsa("primary");
        let (ak_ctx, ak_pub, ak_priv) = s.create_and_load_signing_key(&primary_ctx, "rsa", "ak");
        let (_, _wrong_ak_pub, _) = s.create_and_load_signing_key(&primary_ctx, "rsa", "wrong_ak");

        // Export public keys.
        let ak_tpmt = s.tmp().path().join("ak_tpmt.bin");
        s.cmd("readpublic")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ak_ctx))
            .arg("-o")
            .arg(&ak_tpmt)
            .assert()
            .success();

        let wrong_ak_tpmt = s.tmp().path().join("wrong_ak_tpmt.bin");
        let wrong_ak_ctx_path = s.tmp().path().join("wrong_ak.ctx");
        s.cmd("readpublic")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&wrong_ak_ctx_path))
            .arg("-o")
            .arg(&wrong_ak_tpmt)
            .assert()
            .success();

        s.flush_transient();

        // Generate a nonce.
        let nonce = s.tmp().path().join("nonce.bin");
        s.cmd("getrandom")
            .args(["32", "-o"])
            .arg(&nonce)
            .assert()
            .success();

        // Re-load the AK for quoting.
        let ak_ctx = s.tmp().path().join("ak_reloaded.ctx");
        s.cmd("load")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary_ctx))
            .arg("-r")
            .arg(&ak_priv)
            .arg("-u")
            .arg(&ak_pub)
            .arg("-c")
            .arg(&ak_ctx)
            .assert()
            .success();

        Self {
            s,
            primary_ctx,
            ak_ctx,
            ak_pub,
            ak_priv,
            ak_tpmt,
            wrong_ak_tpmt,
            nonce,
        }
    }

    /// Load the AK external key and return context path.
    fn load_ext_ak(&self, tpmt: &std::path::Path, name: &str) -> std::path::PathBuf {
        self.s.flush_transient();
        let ctx = self.s.tmp().path().join(format!("{name}.ctx"));
        self.s
            .cmd("loadexternal")
            .arg("-u")
            .arg(tpmt)
            .args(["-a", "n", "-c"])
            .arg(&ctx)
            .assert()
            .success();
        ctx
    }

    /// Reload the AK for signing/quoting.
    fn reload_ak(&self) -> std::path::PathBuf {
        self.s.flush_transient();
        let ctx = self.s.tmp().path().join("ak_requoted.ctx");
        self.s
            .cmd("load")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&self.primary_ctx))
            .arg("-r")
            .arg(&self.ak_priv)
            .arg("-u")
            .arg(&self.ak_pub)
            .arg("-c")
            .arg(&ctx)
            .assert()
            .success();
        ctx
    }
}

// ════════════════════════════════════════════════════════════════════
// SUCCESS PATHS
// ════════════════════════════════════════════════════════════════════

#[test]
fn quote_pcrs_with_nonce() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();
    assert!(std::fs::metadata(&msg).unwrap().len() > 0);
    assert!(std::fs::metadata(&sig).unwrap().len() > 0);
    assert!(std::fs::metadata(&pcr).unwrap().len() > 0);
}

#[test]
fn checkquote_full_verification() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-f")
        .arg(&pcr)
        .args(["-l", "sha256:0,1,2", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .assert()
        .success();
}

#[test]
fn checkquote_signature_only() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

#[test]
fn checkquote_nonce_only() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-q")
        .arg(format!("file:{}", setup.nonce.display()))
        .assert()
        .success();
}

#[test]
fn checkquote_pcr_digest_only() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-f")
        .arg(&pcr)
        .assert()
        .success();
}

#[test]
fn checkquote_pcr_selection_only() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .args(["-l", "sha256:0,1,2"])
        .assert()
        .success();
}

#[test]
fn quote_without_nonce() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote2_msg.bin");
    let sig = setup.s.tmp().path().join("quote2_sig.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0", "-g", "sha256", "-m"])
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
    assert!(std::fs::metadata(&msg).unwrap().len() > 0);
    assert!(std::fs::metadata(&sig).unwrap().len() > 0);
}

#[test]
fn quote_with_hex_nonce() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote3_msg.bin");
    let sig = setup.s.tmp().path().join("quote3_sig.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0", "-g", "sha256", "-q", "hex:deadbeef", "-m"])
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();
}

// ════════════════════════════════════════════════════════════════════
// FAILURE PATHS
// ════════════════════════════════════════════════════════════════════

#[test]
fn checkquote_wrong_nonce_fails() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");

    let wrong_nonce = setup.s.tmp().path().join("wrong_nonce.bin");
    setup
        .s
        .cmd("getrandom")
        .args(["32", "-o"])
        .arg(&wrong_nonce)
        .assert()
        .success();

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-f")
        .arg(&pcr)
        .args(["-l", "sha256:0,1,2", "-q"])
        .arg(format!("file:{}", wrong_nonce.display()))
        .assert()
        .failure();
}

#[test]
fn checkquote_wrong_pcr_values_fails() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");
    let bad_pcr = setup.s.corrupt_file(&pcr, "quote_pcr_tampered.bin", 0);

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-f")
        .arg(&bad_pcr)
        .arg("-q")
        .arg(format!("file:{}", setup.nonce.display()))
        .assert()
        .failure();
}

#[test]
fn checkquote_wrong_pcr_selection_fails() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .args(["-l", "sha256:0,1,3", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .assert()
        .failure();
}

#[test]
fn checkquote_wrong_key_fails() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let wrong_ext = setup.load_ext_ak(&setup.wrong_ak_tpmt, "wrong_ak_ext");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&wrong_ext))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-f")
        .arg(&pcr)
        .args(["-l", "sha256:0,1,2", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .assert()
        .failure();
}

#[test]
fn checkquote_corrupted_signature_fails() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");
    let bad_sig = setup.s.corrupt_file(&sig, "quote_sig_corrupt.bin", 20);

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&bad_sig)
        .assert()
        .failure();
}

#[test]
fn checkquote_corrupted_message_fails() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");
    let bad_msg = setup.s.corrupt_file(&msg, "quote_msg_corrupt.bin", 20);

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&bad_msg)
        .arg("-s")
        .arg(&sig)
        .assert()
        .failure();
}

#[test]
fn checkquote_correct_quote_correct_pcrs_wrong_nonce_fails() {
    let setup = AttestSetup::new();
    let msg = setup.s.tmp().path().join("quote_msg.bin");
    let sig = setup.s.tmp().path().join("quote_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:0,1,2", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext");
    let bad_nonce = setup
        .s
        .write_tmp_file("bad_nonce.bin", b"totally_wrong_nonce_data_here!!");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-f")
        .arg(&pcr)
        .arg("-q")
        .arg(format!("file:{}", bad_nonce.display()))
        .assert()
        .failure();
}

// ════════════════════════════════════════════════════════════════════
// ATTESTATION AFTER PCR CHANGE
// ════════════════════════════════════════════════════════════════════

#[test]
fn quote_after_pcr_extend_verifies_with_new_values() {
    let setup = AttestSetup::new();

    // Extend PCR 16.
    setup
        .s
        .cmd("pcrextend")
        .arg("16:sha256=0000000000000000000000000000000000000000000000000000000000000001")
        .assert()
        .success();

    // Re-quote with PCR 16.
    let ak_ctx = setup.reload_ak();
    let msg = setup.s.tmp().path().join("quote_ext_msg.bin");
    let sig = setup.s.tmp().path().join("quote_ext_sig.bin");
    let pcr = setup.s.tmp().path().join("quote_ext_pcr.bin");

    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ak_ctx))
        .args(["-l", "sha256:16", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-o")
        .arg(&pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext2");

    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&msg)
        .arg("-s")
        .arg(&sig)
        .arg("-f")
        .arg(&pcr)
        .args(["-l", "sha256:16", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .assert()
        .success();
}

#[test]
fn old_pcr_values_do_not_verify_with_new_quote() {
    let setup = AttestSetup::new();

    // Get old PCR values via a quote.
    let old_msg = setup.s.tmp().path().join("old_quote_msg.bin");
    let old_sig = setup.s.tmp().path().join("old_quote_sig.bin");
    let old_pcr = setup.s.tmp().path().join("old_quote_pcr.bin");
    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-l", "sha256:16", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&old_msg)
        .arg("-s")
        .arg(&old_sig)
        .arg("-o")
        .arg(&old_pcr)
        .assert()
        .success();

    // Extend PCR 16.
    setup
        .s
        .cmd("pcrextend")
        .arg("16:sha256=0000000000000000000000000000000000000000000000000000000000000001")
        .assert()
        .success();

    // New quote.
    let ak_ctx = setup.reload_ak();
    let new_msg = setup.s.tmp().path().join("new_quote_msg.bin");
    let new_sig = setup.s.tmp().path().join("new_quote_sig.bin");
    let new_pcr = setup.s.tmp().path().join("new_quote_pcr.bin");
    setup
        .s
        .cmd("quote")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&ak_ctx))
        .args(["-l", "sha256:16", "-g", "sha256", "-q"])
        .arg(format!("file:{}", setup.nonce.display()))
        .arg("-m")
        .arg(&new_msg)
        .arg("-s")
        .arg(&new_sig)
        .arg("-o")
        .arg(&new_pcr)
        .assert()
        .success();

    let ext_ctx = setup.load_ext_ak(&setup.ak_tpmt, "ak_ext3");

    // Old PCR values should NOT verify with new quote.
    setup
        .s
        .cmd("checkquote")
        .arg("-u")
        .arg(SwtpmSession::file_ref(&ext_ctx))
        .arg("-m")
        .arg(&new_msg)
        .arg("-s")
        .arg(&new_sig)
        .arg("-f")
        .arg(&old_pcr)
        .arg("-q")
        .arg(format!("file:{}", setup.nonce.display()))
        .assert()
        .failure();
}

// ── NV certify ──────────────────────────────────────────────────────

#[test]
fn nvcertify() {
    let setup = AttestSetup::new();

    setup
        .s
        .cmd("nvdefine")
        .args([
            "-C",
            "o",
            "-s",
            "16",
            "-a",
            "ownerwrite|ownerread",
            "0x01000020",
        ])
        .assert()
        .success();

    let nv_data = setup
        .s
        .write_tmp_file("nv_cert_data.bin", b"nv certify data!");
    setup
        .s
        .cmd("nvwrite")
        .args(["-C", "o", "-i"])
        .arg(&nv_data)
        .arg("0x01000020")
        .assert()
        .success();

    let attest = setup.s.tmp().path().join("nvcert_attest.bin");
    let sig = setup.s.tmp().path().join("nvcert_sig.bin");
    setup
        .s
        .cmd("nvcertify")
        .arg("-C")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args([
            "-i",
            "0x01000020",
            "-c",
            "o",
            "-P",
            "",
            "-g",
            "sha256",
            "-o",
        ])
        .arg(&attest)
        .arg("--signature")
        .arg(&sig)
        .assert()
        .success();
    assert!(std::fs::metadata(&attest).unwrap().len() > 0);

    let _ = setup
        .s
        .cmd("nvundefine")
        .args(["-C", "o", "0x01000020"])
        .ok();
}

// ── Command audit digest ────────────────────────────────────────────

#[test]
fn getcommandauditdigest() {
    let setup = AttestSetup::new();
    let attest = setup.s.tmp().path().join("audit_attest.bin");
    let sig = setup.s.tmp().path().join("audit_sig.bin");
    setup
        .s
        .cmd("getcommandauditdigest")
        .arg("-c")
        .arg(SwtpmSession::file_ref(&setup.ak_ctx))
        .args(["-C", "e", "-o"])
        .arg(&attest)
        .arg("--signature")
        .arg(&sig)
        .assert()
        .success();
    assert!(std::fs::metadata(&attest).unwrap().len() > 0);
}
