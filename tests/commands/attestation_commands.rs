// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 18 — Attestation Commands.

mod quote {
    use crate::common::SwtpmSession;

    struct AttestSetup {
        s: SwtpmSession,
        ak_ctx: std::path::PathBuf,
        nonce: std::path::PathBuf,
    }

    impl AttestSetup {
        fn new() -> Self {
            let s = SwtpmSession::new();
            let primary_ctx = s.create_primary_rsa("primary");
            let (ak_ctx, _, _) = s.create_and_load_signing_key(&primary_ctx, "rsa", "ak");
            let nonce = s.tmp().path().join("nonce.bin");
            s.cmd("getrandom")
                .args(["32", "-o"])
                .arg(&nonce)
                .assert()
                .success();

            Self { s, ak_ctx, nonce }
        }
    }

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
}

mod getcommandauditdigest {
    use crate::common::SwtpmSession;

    #[test]
    fn getcommandauditdigest() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (ak_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "ak");
        let attest = s.tmp().path().join("audit_attest.bin");
        let sig = s.tmp().path().join("audit_sig.bin");
        s.cmd("getcommandauditdigest")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ak_ctx))
            .args(["-C", "e", "-o"])
            .arg(&attest)
            .arg("--signature")
            .arg(&sig)
            .assert()
            .success();
        assert!(std::fs::metadata(&attest).unwrap().len() > 0);
    }
}

mod certify {
    use std::path::PathBuf;

    use crate::common::{SwtpmSession, ecc_signing_public_with_admin_policy};
    use tss_esapi::structures::Digest;

    fn setup_policy_authorization(s: &SwtpmSession) -> (PathBuf, PathBuf, PathBuf) {
        let trial = s.tmp().path().join("certify-trial.ctx");
        let policy_digest = s.tmp().path().join("certify.policy");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&trial)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&trial)
            .arg("0x148")
            .arg("-L")
            .arg(&policy_digest)
            .assert()
            .success();

        let primary = s.create_primary_rsa("policy-primary");
        let policy = Digest::try_from(s.read_file(&policy_digest)).unwrap();
        let (target, _, _) = s.create_and_load_from_public(
            &primary,
            "policy-target",
            &ecc_signing_public_with_admin_policy(policy),
            None,
        );
        let (signer, _, _) = s.create_and_load_signing_key(&primary, "rsa", "policy-signer");

        let policy_session = s.tmp().path().join("certify-policy.ctx");
        s.cmd("startauthsession")
            .args(["--policy-session", "-S"])
            .arg(&policy_session)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&policy_session)
            .arg("0x148")
            .assert()
            .success();

        (target, signer, policy_session)
    }

    #[test]
    fn certify_object() {
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
        assert!(std::fs::metadata(&attest).unwrap().len() > 0);
        assert!(std::fs::metadata(&sig).unwrap().len() > 0);
    }

    #[test]
    fn certify_with_qualification() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (certifier_ctx, _, _) = s.create_and_load_signing_key(&primary, "rsa", "certifier");
        let (target_ctx, _, _) = s.create_and_load_signing_key(&primary, "ecc", "target");

        let attest = s.tmp().path().join("certify_q_attest.bin");
        let sig = s.tmp().path().join("certify_q_sig.bin");
        s.cmd("certify")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&target_ctx))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&certifier_ctx))
            .args(["-g", "sha256", "-q", "hex:cafebabe", "-o"])
            .arg(&attest)
            .arg("-s")
            .arg(&sig)
            .assert()
            .success();
        assert!(std::fs::metadata(&attest).unwrap().len() > 0);
    }

    #[test]
    fn certify_accepts_a_policy_session_for_admin_authorization() {
        let s = SwtpmSession::new();
        let (target, signer, policy_session) = setup_policy_authorization(&s);

        s.cmd("certify")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&target))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&signer))
            .arg("--policy-session")
            .arg(&policy_session)
            .assert()
            .success();
    }

    #[test]
    fn certify_saves_a_supplied_policy_session_for_reuse() {
        let s = SwtpmSession::new();
        let (target, signer, policy_session) = setup_policy_authorization(&s);
        s.cmd("certify")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&target))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&signer))
            .arg("--policy-session")
            .arg(&policy_session)
            .assert()
            .success();

        let continued_policy = s.tmp().path().join("continued-certify.policy");
        s.cmd("policygetdigest")
            .arg("-S")
            .arg(&policy_session)
            .arg("-o")
            .arg(&continued_policy)
            .assert()
            .success();
        assert_eq!(s.read_file(&continued_policy).len(), 32);
    }
}

mod certifycreation {
    use crate::common::SwtpmSession;

    #[test]
    fn certifycreation_outputs_creation_attestation() {
        let s = SwtpmSession::new();
        let parent = s.create_primary_rsa("signing-parent");
        let (signing_key, _, _) = s.create_and_load_signing_key(&parent, "rsa", "signing-key");

        let object = s.tmp().path().join("created-object.ctx");
        let creation_hash = s.tmp().path().join("creation-hash.bin");
        let creation_ticket = s.tmp().path().join("creation-ticket.bin");
        s.cmd("createprimary")
            .arg("--context")
            .arg(&object)
            .arg("--creation-hash")
            .arg(&creation_hash)
            .arg("--creation-ticket")
            .arg(&creation_ticket)
            .assert()
            .success();

        let attestation = s.tmp().path().join("creation-attestation.bin");
        let signature = s.tmp().path().join("creation-signature.bin");
        s.cmd("certifycreation")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&signing_key))
            .arg("-c")
            .arg(SwtpmSession::file_ref(&object))
            .arg("-d")
            .arg(&creation_hash)
            .arg("-t")
            .arg(&creation_ticket)
            .arg("-o")
            .arg(&attestation)
            .arg("-s")
            .arg(&signature)
            .assert()
            .success();

        assert!(std::fs::metadata(attestation).unwrap().len() > 0);
        assert!(std::fs::metadata(signature).unwrap().len() > 0);
    }
}

mod certifyx509 {
    use std::path::PathBuf;

    use crate::common::{SwtpmSession, x509_signing_public};

    fn setup_objects(s: &SwtpmSession) -> (PathBuf, PathBuf, PathBuf) {
        let object = s.create_primary_from_public("x509-object", &x509_signing_public());
        let signing_key = s.create_primary_from_public("x509-signer", &x509_signing_public());
        let partial = s.write_tmp_file("partial-certificate.der", &partial_certificate());

        (object, signing_key, partial)
    }

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() <= u8::MAX as usize);
        let mut encoded = vec![tag];
        if value.len() < 128 {
            encoded.push(value.len() as u8);
        } else {
            encoded.extend_from_slice(&[0x81, value.len() as u8]);
        }
        encoded.extend_from_slice(value);
        encoded
    }

    fn distinguished_name(common_name: &str) -> Vec<u8> {
        let attribute = der(
            0x30,
            &[
                der(0x06, &[0x55, 0x04, 0x03]),
                der(0x0c, common_name.as_bytes()),
            ]
            .concat(),
        );
        der(0x30, &der(0x31, &attribute))
    }

    fn partial_certificate() -> Vec<u8> {
        let name = distinguished_name("rust-tpm2-cli test");
        let validity = der(
            0x30,
            &[der(0x17, b"260101000000Z"), der(0x17, b"400101000000Z")].concat(),
        );
        let subject_public_key_info = der(
            0x30,
            &[
                der(
                    0x30,
                    &der(
                        0x06,
                        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                    ),
                ),
                der(0x03, &[0]),
            ]
            .concat(),
        );
        let key_usage = der(
            0x30,
            &[
                der(0x06, &[0x55, 0x1d, 0x0f]),
                der(0x01, &[0xff]),
                der(0x04, &der(0x03, &[2, 0x84])),
            ]
            .concat(),
        );
        let extensions = der(0xa3, &der(0x30, &key_usage));
        der(
            0x30,
            &[
                name.clone(),
                validity,
                name,
                subject_public_key_info,
                extensions,
            ]
            .concat(),
        )
    }

    #[test]
    fn certifyx509_outputs_certificate_components() {
        let s = SwtpmSession::new();
        let (object, signing_key, partial) = setup_objects(&s);
        let added = s.tmp().path().join("added-certificate.der");
        let digest = s.tmp().path().join("tbs-digest.bin");
        let signature = s.tmp().path().join("certificate-signature.bin");

        s.cmd("certifyx509")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&object))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&signing_key))
            .arg("-i")
            .arg(&partial)
            .arg("-o")
            .arg(&added)
            .arg("-d")
            .arg(&digest)
            .arg("-s")
            .arg(&signature)
            .assert()
            .success();

        assert!(std::fs::metadata(added).unwrap().len() > 0);
        assert_eq!(std::fs::metadata(digest).unwrap().len(), 32);
        assert!(std::fs::metadata(signature).unwrap().len() > 0);
    }

    #[test]
    fn certifyx509_saves_a_supplied_session_for_reuse() {
        let s = SwtpmSession::new();
        let (object, signing_key, partial) = setup_objects(&s);
        let command_session = s.tmp().path().join("certify-x509-command-session.ctx");
        s.cmd("startauthsession")
            .args(["--hmac-session", "-S"])
            .arg(&command_session)
            .assert()
            .success();

        s.cmd("certifyx509")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&object))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&signing_key))
            .arg("-i")
            .arg(&partial)
            .arg("--session")
            .arg(&command_session)
            .assert()
            .success();

        s.cmd("pcrreset")
            .arg("16")
            .arg("--session")
            .arg(&command_session)
            .assert()
            .success();
    }
}

mod gettime {
    use crate::common::SwtpmSession;

    #[test]
    fn gettime_produces_attestation_and_signature() {
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
        assert!(std::fs::metadata(&attest).unwrap().len() > 0);
        assert!(std::fs::metadata(&sig).unwrap().len() > 0);
    }

    #[test]
    fn gettime_without_nonce() {
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
        assert!(std::fs::metadata(&attest).unwrap().len() > 0);
    }
}

mod getsessionauditdigest {
    use crate::common::SwtpmSession;

    #[test]
    fn getsessionauditdigest_reports_an_audited_command() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (signing_key, _, _) = s.create_and_load_signing_key(&primary, "rsa", "audit-key");
        let session = s.tmp().path().join("audit-session.ctx");
        s.cmd("startauthsession")
            .args(["--audit-session", "-S"])
            .arg(&session)
            .assert()
            .success();
        s.cmd("getrandom")
            .arg("8")
            .arg("-o")
            .arg(s.tmp().path().join("random.bin"))
            .arg("-S")
            .arg(&session)
            .assert()
            .success();

        let attestation = s.tmp().path().join("session-audit.bin");
        let signature = s.tmp().path().join("session-audit.sig");
        s.cmd("getsessionauditdigest")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&signing_key))
            .arg("-S")
            .arg(&session)
            .arg("-o")
            .arg(&attestation)
            .arg("--signature")
            .arg(&signature)
            .assert()
            .success();

        assert!(std::fs::metadata(attestation).unwrap().len() > 0);
        assert!(std::fs::metadata(signature).unwrap().len() > 0);
    }

    #[test]
    fn getsessionauditdigest_rejects_a_session_without_audit_history() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");
        let (signing_key, _, _) = s.create_and_load_signing_key(&primary, "rsa", "audit-key");
        s.cmd("evictcontrol")
            .args(["-C", "o", "-c"])
            .arg(SwtpmSession::file_ref(&signing_key))
            .arg("0x81000021")
            .assert()
            .success();
        let session = s.tmp().path().join("audit-session.ctx");
        s.cmd("startauthsession")
            .args(["--hmac-session", "-S"])
            .arg(&session)
            .assert()
            .success();
        s.cmd("sessionconfig")
            .arg("-S")
            .arg(&session)
            .arg("--enable-audit")
            .assert()
            .success();
        let attestation = s.tmp().path().join("session-audit.bin");
        let signature = s.tmp().path().join("session-audit.sig");
        s.cmd("getsessionauditdigest")
            .arg("-c")
            .arg("hex:0x81000021")
            .arg("-S")
            .arg(&session)
            .arg("-o")
            .arg(&attestation)
            .arg("--signature")
            .arg(&signature)
            .assert()
            .failure();
    }
}
