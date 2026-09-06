// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 Library Specification, Part 3, Section 12 — Object Commands.

mod activatecredential {
    use crate::common::SwtpmSession;

    #[test]
    fn activatecredential_recovers_the_credential() {
        let s = SwtpmSession::new();
        let (ek_context, ek_public, ak_context, ak_name) = s.create_credential_keys();
        let secret = s.write_tmp_file("secret.bin", b"secret credential");
        let credential = s.tmp().path().join("credential.bin");
        s.cmd("makecredential")
            .arg("-u")
            .arg(&ek_public)
            .arg("-s")
            .arg(&secret)
            .arg("-n")
            .arg(&ak_name)
            .arg("-o")
            .arg(&credential)
            .assert()
            .success();

        let command_session = s.tmp().path().join("activate-command-session.ctx");
        s.cmd("startauthsession")
            .args(["--hmac-session", "-S"])
            .arg(&command_session)
            .assert()
            .success();

        let recovered = s.tmp().path().join("recovered.bin");
        s.cmd("activatecredential")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ak_context))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&ek_context))
            .arg("-i")
            .arg(&credential)
            .arg("-o")
            .arg(&recovered)
            .arg("--session")
            .arg(&command_session)
            .assert()
            .success();
        assert_eq!(s.read_file(&recovered), b"secret credential");

        s.cmd("pcrreset")
            .arg("16")
            .arg("--session")
            .arg(&command_session)
            .assert()
            .success();
    }

    #[test]
    fn activatecredential_corrupted_blob_fails() {
        let s = SwtpmSession::new();
        let (ek_ctx, ek_pub, ak_ctx, ak_name) = s.create_credential_keys();

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
}

mod changeauth {
    use crate::common::{SwtpmSession, ecc_signing_public_with_admin_policy};
    use tss_esapi::structures::Digest;

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

    #[test]
    fn changeauth_accepts_a_policy_session_for_object_admin_authorization() {
        let s = SwtpmSession::new();
        let trial = s.tmp().path().join("change-auth-trial.ctx");
        let policy_digest = s.tmp().path().join("change-auth.policy");
        s.cmd("startauthsession")
            .arg("-S")
            .arg(&trial)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&trial)
            .arg("0x150")
            .arg("-L")
            .arg(&policy_digest)
            .assert()
            .success();

        let parent = s.create_primary_rsa("policy-parent");
        let policy = Digest::try_from(s.read_file(&policy_digest)).unwrap();
        let (object, _, _) = s.create_and_load_from_public(
            &parent,
            "policy-object",
            &ecc_signing_public_with_admin_policy(policy),
            None,
        );

        let policy_session = s.tmp().path().join("change-auth-policy.ctx");
        s.cmd("startauthsession")
            .args(["--policy-session", "-S"])
            .arg(&policy_session)
            .assert()
            .success();
        s.cmd("policycommandcode")
            .arg("-S")
            .arg(&policy_session)
            .arg("0x150")
            .assert()
            .success();

        let new_private = s.tmp().path().join("policy-object-new.priv");
        s.cmd("changeauth")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&object))
            .arg("-C")
            .arg(SwtpmSession::file_ref(&parent))
            .arg("-r")
            .arg("new-auth")
            .arg("-o")
            .arg(&new_private)
            .arg("--policy-session")
            .arg(&policy_session)
            .assert()
            .success();
        assert!(new_private.exists());
    }
}

mod create {
    use crate::common::SwtpmSession;

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
}

mod load {
    use crate::common::SwtpmSession;

    #[test]
    fn load_ecc_child_key() {
        let s = SwtpmSession::new();
        let primary_ctx = s.create_primary_rsa("primary");
        let (ctx, _, _) = s.create_and_load_signing_key(&primary_ctx, "ecc", "child_ecc");
        assert!(ctx.exists());
    }

    #[test]
    fn load_rsa_child_key() {
        let s = SwtpmSession::new();
        let primary_ctx = s.create_primary_rsa("primary");
        let (ctx, _, _) = s.create_and_load_signing_key(&primary_ctx, "rsa", "child_rsa");
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
}

mod loadexternal {
    use crate::common::SwtpmSession;
    use tss_esapi::attributes::ObjectAttributesBuilder;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    };
    use tss_esapi::structures::{
        EccParameter, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder, Sensitive,
    };
    use tss_esapi::traits::Marshall;

    fn external_ecc_key(s: &SwtpmSession) -> (tss_esapi::structures::Public, Sensitive) {
        let output = s
            .cmd("geteccparameters")
            .arg("ecc256")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let parameters: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let coordinate = |name| {
            EccParameter::try_from(
                hex::decode(parameters[name].as_str().expect("missing ECC parameter")).unwrap(),
            )
            .unwrap()
        };
        let unique = EccPoint::new(coordinate("gX"), coordinate("gY"));
        let attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .build()
            .unwrap();
        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .with_restricted(false)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .unwrap(),
            )
            .with_ecc_unique_identifier(unique)
            .build()
            .unwrap();
        let mut scalar = vec![0; 32];
        scalar[31] = 1;
        let sensitive = Sensitive::Ecc {
            sensitive: EccParameter::try_from(scalar).unwrap(),
            auth_value: Default::default(),
            seed_value: Default::default(),
        };
        (public, sensitive)
    }

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

    #[test]
    fn loadexternal_private_and_public_key() {
        let s = SwtpmSession::new();
        let (public_area, sensitive) = external_ecc_key(&s);
        let public = s.write_tmp_file("external-ecc.pub", &public_area.marshall().unwrap());
        let private = s.write_tmp_file("external-ecc.priv", &sensitive.marshall().unwrap());
        let context = s.tmp().path().join("external-ecc.ctx");

        s.cmd("loadexternal")
            .arg("-u")
            .arg(public)
            .arg("-r")
            .arg(private)
            .arg("-c")
            .arg(&context)
            .assert()
            .success();
        s.cmd("readpublic")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&context))
            .assert()
            .success();
    }
}

mod makecredential {
    use crate::common::SwtpmSession;

    #[test]
    fn makecredential_outputs_a_credential_blob() {
        let s = SwtpmSession::new();
        let (_, ek_public, _, ak_name) = s.create_credential_keys();
        let secret = s.write_tmp_file("secret.bin", b"secret credential");
        let credential = s.tmp().path().join("credential.bin");
        s.cmd("makecredential")
            .arg("-u")
            .arg(&ek_public)
            .arg("-s")
            .arg(&secret)
            .arg("-n")
            .arg(&ak_name)
            .arg("-o")
            .arg(&credential)
            .assert()
            .success();
        assert!(std::fs::metadata(credential).unwrap().len() > 0);
    }
}

mod readpublic {
    use crate::common::SwtpmSession;

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
}

mod unseal {
    use crate::common::SwtpmSession;

    #[test]
    fn unseal_with_wrong_auth_fails() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");

        let input = s.write_tmp_file("seal_input.bin", b"secret");
        let priv_f = s.tmp().path().join("sealed.priv");
        let pub_f = s.tmp().path().join("sealed.pub");
        s.cmd("create")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .args(["-G", "keyedhash", "-g", "sha256", "-i"])
            .arg(&input)
            .args(["-p", "sealpass", "-r"])
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .assert()
            .success();

        let ctx = s.tmp().path().join("sealed.ctx");
        s.cmd("load")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-r")
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .arg("-c")
            .arg(&ctx)
            .assert()
            .success();

        s.cmd("unseal")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ctx))
            .args(["-p", "wrongpass", "-o"])
            .arg(s.tmp().path().join("out.bin"))
            .assert()
            .failure();
    }

    #[test]
    fn unseal_with_the_correct_auth_returns_the_data() {
        let s = SwtpmSession::new();
        let primary = s.create_primary_rsa("primary");

        let input = s.write_tmp_file("seal_input.bin", b"secret");
        let priv_f = s.tmp().path().join("sealed.priv");
        let pub_f = s.tmp().path().join("sealed.pub");
        s.cmd("create")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .args(["-G", "keyedhash", "-g", "sha256", "-i"])
            .arg(&input)
            .args(["-p", "sealpass", "-r"])
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .assert()
            .success();

        s.flush_transient();

        let ctx = s.tmp().path().join("sealed.ctx");
        s.cmd("load")
            .arg("-C")
            .arg(SwtpmSession::file_ref(&primary))
            .arg("-r")
            .arg(&priv_f)
            .arg("-u")
            .arg(&pub_f)
            .arg("-c")
            .arg(&ctx)
            .assert()
            .success();

        s.cmd("unseal")
            .arg("-c")
            .arg(SwtpmSession::file_ref(&ctx))
            .args(["-p", "sealpass", "-o"])
            .arg(s.tmp().path().join("out.bin"))
            .assert()
            .success();
        assert_eq!(s.read_file(&s.tmp().path().join("out.bin")), b"secret");
    }
}
