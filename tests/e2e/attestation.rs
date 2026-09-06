// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for attestation.

mod quote_verification {
    use crate::common::SwtpmSession;

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
            let (ak_ctx, ak_pub, ak_priv) =
                s.create_and_load_signing_key(&primary_ctx, "rsa", "ak");
            let (_, _wrong_ak_pub, _) =
                s.create_and_load_signing_key(&primary_ctx, "rsa", "wrong_ak");

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

    #[test]
    fn e2e_checkquote_corrupted_message_fails() {
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
    fn e2e_checkquote_corrupted_signature_fails() {
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
    fn e2e_checkquote_full_verification() {
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
    fn e2e_checkquote_nonce_only() {
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
    fn e2e_checkquote_pcr_digest_only() {
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
    fn e2e_checkquote_pcr_selection_only() {
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
    fn e2e_checkquote_signature_only() {
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
    fn e2e_checkquote_wrong_key_fails() {
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
    fn e2e_checkquote_wrong_nonce_fails() {
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
    fn e2e_checkquote_wrong_pcr_selection_fails() {
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
    fn e2e_checkquote_wrong_pcr_values_fails() {
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
    fn e2e_old_pcr_values_do_not_verify_with_new_quote() {
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

    #[test]
    fn e2e_quote_after_pcr_extend_verifies_with_new_values() {
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
}

mod certify_signature_verification {
    use crate::common::SwtpmSession;

    #[test]
    fn e2e_verifysignature_certify_corrupted_data_fails() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
        let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");

        let attest = s.tmp().path().join("certify_attest.bin");
        let sig = s.tmp().path().join("certify_sig.bin");
        s.cmd("certify")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&target_ctx))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&certifier_ctx))
            .args(["-g", "sha256", "-o"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();

        let bad_attest = s.corrupt_file(&attest, "certify_attest_bad.bin", 10);

        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&certifier_ctx))
            .args(["-g", "sha256", "-m"])
            .arg(&bad_attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .failure();
    }

    #[test]
    fn e2e_verifysignature_certify_wrong_key_fails() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
        let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");
        let (wrong_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "wrong_cert");

        let attest = s.tmp().path().join("certify_attest.bin");
        let sig = s.tmp().path().join("certify_sig.bin");
        s.cmd("certify")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&target_ctx))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&certifier_ctx))
            .args(["-g", "sha256", "-o"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();

        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&wrong_ctx))
            .args(["-g", "sha256", "-m"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .failure();
    }

    #[test]
    fn e2e_verifysignature_on_certify_attestation() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
        let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");

        let attest = s.tmp().path().join("certify_attest.bin");
        let sig = s.tmp().path().join("certify_sig.bin");
        s.cmd("certify")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&target_ctx))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&certifier_ctx))
            .args(["-g", "sha256", "-o"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();

        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&certifier_ctx))
            .args(["-g", "sha256", "-m"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();
    }
}

mod time_attestation_verification {
    use crate::common::SwtpmSession;

    #[test]
    fn e2e_verifysignature_gettime_corrupted_attestation_fails() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_ecc("primary");
        let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");

        let attest = s.tmp().path().join("time_attest.bin");
        let sig = s.tmp().path().join("time_sig.bin");
        s.cmd("gettime")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key_ctx))
            .args(["-g", "sha256", "-o"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();

        let bad_attest = s.corrupt_file(&attest, "time_attest_bad.bin", 10);

        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key_ctx))
            .args(["-g", "sha256", "-m"])
            .arg(&bad_attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .failure();
    }

    #[test]
    fn e2e_verifysignature_gettime_wrong_key_fails() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_ecc("primary");
        let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");
        let (wrong_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "wrong_key");

        let attest = s.tmp().path().join("time_attest.bin");
        let sig = s.tmp().path().join("time_sig.bin");
        s.cmd("gettime")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key_ctx))
            .args(["-g", "sha256", "-o"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();

        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&wrong_ctx))
            .args(["-g", "sha256", "-m"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .failure();
    }

    #[test]
    fn e2e_verifysignature_on_gettime_attestation() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_ecc("primary");
        let (key_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "ts_key");
        let nonce = s.tmp().path().join("nonce.bin");
        s.cmd("getrandom")
            .args(["32", "-o"])
            .arg(&nonce)
            .assert()
            .success();

        let attest = s.tmp().path().join("time_attest.bin");
        let sig = s.tmp().path().join("time_sig.bin");
        s.cmd("gettime")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key_ctx))
            .args(["-g", "sha256", "-q"])
            .arg(format!("file:{}", nonce.display()))
            .arg("-o")
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();

        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key_ctx))
            .args(["-g", "sha256", "-m"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();
    }
}
