// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 20 — Signing and Signature Verification.

mod sign {
    use crate::common::SwtpmSession;

    /// Setup helper: creates primary, signing keys, and a hash+ticket for signing.
    struct SignSetup {
        session: SwtpmSession,
        rsa_ctx: std::path::PathBuf,
        ecc_ctx: std::path::PathBuf,
        digest_file: std::path::PathBuf,
        ticket_file: std::path::PathBuf,
    }

    impl SignSetup {
        fn new() -> Self {
            let s = SwtpmSession::new();
            let primary = s.create_primary_rsa("primary");
            let (rsa_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "sign_rsa");
            let (ecc_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "sign_ecc");

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
                digest_file,
                ticket_file,
            }
        }
    }

    #[test]
    fn sign_ecc_ecdsa() {
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
    fn sign_rsa_rsassa() {
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
}

mod verifysignature {
    use crate::common::SwtpmSession;

    #[test]
    fn verifysignature_accepts_a_valid_signature() {
        let s = SwtpmSession::new();
        let parent = s.create_primary_rsa("primary");
        let (key, _, _) = s.create_and_load_signing_key(&parent, "rsa", "signing-key");
        let digest = s.write_tmp_file("digest.bin", &[0x42; 32]);
        let signature = s.tmp().path().join("signature.bin");
        s.cmd("sign")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .args(["-g", "sha256", "-s", "rsassa", "-d"])
            .arg(&digest)
            .arg("-o")
            .arg(&signature)
            .assert()
            .success();

        let ticket = s.tmp().path().join("verification-ticket.bin");
        s.cmd("verifysignature")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&key))
            .arg("-d")
            .arg(&digest)
            .arg("-s")
            .arg(&signature)
            .arg("-t")
            .arg(&ticket)
            .assert()
            .success();
        assert!(std::fs::metadata(ticket).unwrap().len() > 0);
    }
}
